from pox.core import core

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

from pox.lib.recoco import Timer

from collections import defaultdict

from pox.openflow.discovery import Discovery

from pox.lib.util import dpid_to_str

import time


log = core.getLogger()


switches = {}
mac_map = {}
waiting_paths = {}


adjacency = defaultdict(lambda:defaultdict(lambda:None))
switches_bw = defaultdict(lambda: defaultdict(int))

FLOOD_HOLDDOWN = 5
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30
PATH_SETUP_TIME = 4


def measure_link_bw(num, info):
  if len(info) != 0:
      for p in switches.values():
        for q in switches.values():
            print(str(i).split(" ")[2][0])
          #if  str(i).split(" ")[2][0]== str(q) and str(adjacency[q][p])==str(i).split(" ")[4][0]:
            #if byte[p][q]>0:
              #thr[p][q] = (j - byte[p][q]) * 8.0 / (time.time()-clock[p][q])    

def minimum_distance(distance, Q):
  min = float('inf')
  node = 0
  for v in Q:
    if distance[v] < min:
      min = distance[v]
      node = v

  return node

def _get_raw_path(src, dst):
  distance = {}
  previous = {}
  #measure_link_bw(1, ['switch', 'inport'])
  #print("SWITCHES BW: ", switches_bw)
  #time.sleep(15)

  sws = switches.values()

  for dpid in sws:
    distance[dpid] = float('Inf')
    previous[dpid] = None

  distance[src] = 0

  Q=set(sws)

  while len(Q) > 0:
    u = minimum_distance(distance, Q)
    Q.remove(u)
    for p in sws:
      if adjacency[u][p] != None:
        w = 1
        if distance[u] + w < distance[p]:
            distance[p] = distance[u] + w
            previous[p] = u

  r=[]
  p=dst
  r.append(p)
  q=previous[p]

  while q is not None:
    if q == src:
      r.append(q)
      break
    p=q
    r.append(p)
    q=previous[p]
  r.reverse()

  if src==dst:
    path=[src]
  else:
    path=r

  return path


def _check_path (p):

  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:

      return False

    if adjacency[b[0]][a[0]] != b[1]:

      return False

  return True

def _get_path (src, dst, first_port, final_port):

  if src == dst:

    path = [src]

  else:

    path = _get_raw_path(src, dst)

    if path is None: return None

    print "src=",src," dst=",dst

    print time.time(),": ",path

  r = []

  in_port = first_port

  for s1,s2 in zip(path[:-1],path[1:]):

    out_port = adjacency[s1][s2]

    r.append((s1,in_port,out_port))

    in_port = adjacency[s2][s1]

  r.append((dst,in_port,final_port))


  assert _check_path(r), "Illegal path!"


  return r

class WaitingPath (object):

  def __init__ (self, path, packet):

    self.expires_at = time.time() + PATH_SETUP_TIME

    self.path = path

    self.first_switch = path[0][0].dpid

    self.xids = set()

    self.packet = packet


    if len(waiting_paths) > 1000:

      WaitingPath.expire_waiting_paths()


  def add_xid (self, dpid, xid):

    self.xids.add((dpid,xid))

    waiting_paths[(dpid,xid)] = self

  @property

  def is_expired (self):

    return time.time() >= self.expires_at

  def notify (self, event):

    self.xids.discard((event.dpid,event.xid))

    if len(self.xids) == 0:

      if self.packet:

        log.debug("Sending delayed packet out %s"

                  % (dpid_to_str(self.first_switch),))

        msg = of.ofp_packet_out(data=self.packet,

            action=of.ofp_action_output(port=of.OFPP_TABLE))

        core.openflow.sendToDPID(self.first_switch, msg)


      core.l2_multi.raiseEvent(PathInstalled(self.path))

  @staticmethod

  def expire_waiting_paths ():

    packets = set(waiting_paths.values())

    killed = 0

    for p in packets:

      if p.is_expired:

        killed += 1

        for entry in p.xids:

          waiting_paths.pop(entry, None)

    if killed:

      log.error("%i paths failed to install" % (killed,))


class PathInstalled (Event):

  def __init__ (self, path):

    Event.__init__(self)

    self.path = path

class Switch (EventMixin):

  def __init__ (self):

    self.connection = None

    self.ports = None

    self.dpid = None

    self._listeners = None

    self._connected_at = None

  def __repr__ (self):

    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, buf = None):

    msg = of.ofp_flow_mod()

    msg.match = match

    msg.match.in_port = in_port

    msg.idle_timeout = FLOW_IDLE_TIMEOUT

    msg.hard_timeout = FLOW_HARD_TIMEOUT

    msg.actions.append(of.ofp_action_output(port = out_port))

    msg.buffer_id = buf

    switch.connection.send(msg)

  def _install_path (self, p, match, packet_in=None):

    wp = WaitingPath(p, packet_in)

    for sw,in_port,out_port in p:

      self._install(sw, in_port, out_port, match)

      msg = of.ofp_barrier_request()

      sw.connection.send(msg)

      wp.add_xid(sw.dpid,msg.xid)

  def install_path (self, dst_sw, last_port, match, event):

    p = _get_path(self, dst_sw, event.port, last_port)

    if p is None:

      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)

      import pox.lib.packet as pkt


      if (match.dl_type == pkt.ethernet.IP_TYPE and

          event.parsed.find('ipv4')):

        log.debug("Dest unreachable (%s -> %s)",

                  match.dl_src, match.dl_dst)

        from pox.lib.addresses import EthAddr

        e = pkt.ethernet()

        e.src = EthAddr(dpid_to_str(self.dpid)) 

        e.dst = match.dl_src

        e.type = e.IP_TYPE

        ipp = pkt.ipv4()

        ipp.protocol = ipp.ICMP_PROTOCOL

        ipp.srcip = match.nw_dst 

        ipp.dstip = match.nw_src

        icmp = pkt.icmp()

        icmp.type = pkt.ICMP.TYPE_DEST_UNREACH

        icmp.code = pkt.ICMP.CODE_UNREACH_HOST

        orig_ip = event.parsed.find('ipv4')



        d = orig_ip.pack()

        d = d[:orig_ip.hl * 4 + 8]

        import struct

        d = struct.pack("!HH", 0,0) + d 

        icmp.payload = d

        ipp.payload = icmp

        e.payload = ipp

        msg = of.ofp_packet_out()

        msg.actions.append(of.ofp_action_output(port = event.port))

        msg.data = e.pack()

        self.connection.send(msg)


      return

    log.debug("Installing path for %s -> %s %04x (%i hops)",

        match.dl_src, match.dl_dst, match.dl_type, len(p))

    self._install_path(p, match, event.ofp)

    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]

    self._install_path(p, match.flip())




  def _handle_PacketIn (self, event):

    def flood ():

      if self.is_holding_down:

        log.warning("Not flooding -- holddown active")

      msg = of.ofp_packet_out()

      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))

      msg.buffer_id = event.ofp.buffer_id

      msg.in_port = event.port

      self.connection.send(msg)

 

    def drop ():

      if event.ofp.buffer_id is not None:

        msg = of.ofp_packet_out()

        msg.buffer_id = event.ofp.buffer_id

        event.ofp.buffer_id = None

        msg.in_port = event.port

        self.connection.send(msg)

    packet = event.parsed



    loc = (self, event.port)

    oldloc = mac_map.get(packet.src)


    if packet.effective_ethertype == packet.LLDP_TYPE:

      drop()

      return

    if oldloc is None:

      if packet.src.is_multicast == False:

        mac_map[packet.src] = loc
        log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])

    elif oldloc != loc:

      if core.openflow_discovery.is_edge_port(loc[0].dpid, loc[1]):

        log.debug("%s moved from %s.%i to %s.%i?", packet.src,

                  dpid_to_str(oldloc[0].dpid), oldloc[1],

                  dpid_to_str(   loc[0].dpid),    loc[1])

        if packet.src.is_multicast == False:

          mac_map[packet.src] = loc 

          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])

      elif packet.dst.is_multicast == False:

        if packet.dst in mac_map:

          log.warning("Packet from %s to known destination %s arrived "

                      "at %s.%i without flow", packet.src, packet.dst,

                      dpid_to_str(self.dpid), event.port)

    if packet.dst.is_multicast:

      log.debug("Flood multicast from %s", packet.src)

      flood()

    else:

      if packet.dst not in mac_map:

        log.debug("%s unknown -- flooding" % (packet.dst,))

        flood()

      else:

        dest = mac_map[packet.dst]

        match = of.ofp_match.from_packet(packet)

        self.install_path(dest[0], dest[1], match, event)

  def disconnect (self):

    if self.connection is not None:

      log.debug("Disconnect %s" % (self.connection,))

      self.connection.removeListeners(self._listeners)

      self.connection = None

      self._listeners = None

  def connect (self, connection):

    if self.dpid is None:

      self.dpid = connection.dpid

    assert self.dpid == connection.dpid

    if self.ports is None:

      self.ports = connection.features.ports

    self.disconnect()

    log.debug("Connect %s" % (connection,))

    self.connection = connection

    self._listeners = self.listenTo(connection)

    self._connected_at = time.time()

  @property

  def is_holding_down (self):

    if self._connected_at is None: return True

    if time.time() - self._connected_at > FLOOD_HOLDDOWN:

      return False

    return True

  def _handle_ConnectionDown (self, event):

    self.disconnect()

class l2_multi (EventMixin):

  _eventMixin_events = set([

    PathInstalled,

  ])


  def __init__ (self):

    def startup ():

      core.openflow.addListeners(self, priority=0)

      core.openflow_discovery.addListeners(self)

    core.call_when_ready(startup, ('openflow','openflow_discovery'))

  def _handle_portstats_received(self,event):
    for f in event.stats:
      if int(f.port_no)<65534:
        current_bytes = f.rx_bytes + f.tx_bytes
        try:
          last_bytes = self.switches_bw[int(event.connection.dpid)][int(f.port_no)]
        except:
          last_bytes = 0
        estim_bw = (((current_bytes - last_bytes)/1024)/1024)*8
        estim_bw = float(format(estim_bw, '.2f'))
        if estim_bw > 0:
          print pox.lib.util.dpidToStr(event.connection.dpid), f.port_no, estim_bw
        switches_bw[int(event.connection.dpid)][int(f.port_no)] = (f.rx_bytes + f.tx_bytes)

  def _handle_LinkEvent (self, event):

    def flip (link):

      return Discovery.Link(link[2],link[3], link[0],link[1])


    l = event.link

    sw1 = switches[l.dpid1]

    sw2 = switches[l.dpid2]

    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)

    for sw in switches.itervalues():
      if sw.connection is None: continue

      sw.connection.send(clear)

    if event.removed:

      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]

      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]

      for ll in core.openflow_discovery.adjacency:

        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:

          if flip(ll) in core.openflow_discovery.adjacency:

            adjacency[sw1][sw2] = ll.port1

            adjacency[sw2][sw1] = ll.port2

            break

    else:

      if adjacency[sw1][sw2] is None:

        if flip(l) in core.openflow_discovery.adjacency:

          adjacency[sw1][sw2] = l.port1

          adjacency[sw2][sw1] = l.port2

      bad_macs = set()

      for mac,(sw,port) in mac_map.iteritems():

        if sw is sw1 and port == l.port1: bad_macs.add(mac)

        if sw is sw2 and port == l.port2: bad_macs.add(mac)

      for mac in bad_macs:

        log.debug("Unlearned %s", mac)

        del mac_map[mac]

  def _handle_ConnectionUp (self, event):

    sw = switches.get(event.dpid)

    if sw is None:

      # New switch

      sw = Switch()

      switches[event.dpid] = sw

      sw.connect(event.connection)

    else:

      sw.connect(event.connection)

  def _handle_BarrierIn (self, event):

    wp = waiting_paths.pop((event.dpid,event.xid), None)

    if not wp:

      #log.info("No waiting packet %s,%s", event.dpid, event.xid)

      return

    #log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)

    wp.notify(event)



def launch ():

  core.registerNew(l2_multi)

  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)

  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)

