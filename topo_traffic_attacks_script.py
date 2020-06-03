#!/usr/bin/envh python

from mininet.net  import Mininet
import psutil, os

from mininet.node import RemoteController
from mininet.node import CPULimitedHost

from mininet.link import TCLink

from mininet.cli  import CLI
from mininet.util import dumpNodeConnections

from mininet.util import quietRun
import random
import threading
from multiprocessing import Queue

import matplotlib.pyplot as plt

import time

threadLock = threading.Lock()


proc_usage = "awk \'{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else print ($2+$4-u1) * 100 / (t-t1) \"\"; }\' <(grep \'cpu \' /proc/stat) <(sleep 1;grep \'cpu \' /proc/stat)"

def visualize_application(applications):
    x = [i for i in range(1, len(applications) + 1)]
    print(applications)
    plt.plot(x, applications, lw = 5, color = 'r')
    plt.xlabel('Tick', fontsize = 20, color = 'blue')
    plt.ylabel('Applications', fontsize=20, color='blue')
    plt.xticks(range(1, 6500, 250))
    plt.yticks(range(1, 5000, 200))
    plt.grid(True)
    plt.show()

def get_data(sw_path, flow_path, traffic_path):
    sw_data = []
    with open(sw_path) as f:
        for line in f:
            try:
                sw_data.append([int(x) % 1001 for x in line.split()])
            except:
                break

    flow_data = {}
    flow_nums = []
    with open(flow_path) as f:
        for line in f:
            try:
                src, dst = [int(x) for x in line.split()]
            except:
                break
            flow_nums.append((src, dst))
            if src in flow_data:
                flow_data[src].append(dst)
            else:
                flow_data[src] = [dst]

    route_application = []
    applications = 0

    traffic_data = {}
    packages = {}
    prev_tick = 0
    with open(traffic_path) as f:
        for line in f:
            try:
                flow_num, tick, flow_lifetime = [int(x) for x in line.split()]
            except:
                break

            if tick != prev_tick and prev_tick != 0:
                route_application.append(applications)
                applications = 0
                traffic_data[prev_tick] = packages
                packages = {}

            applications += random.randint(1, 4)
            src_dst = flow_nums[flow_num-1]
            if src_dst in packages:
                packages[src_dst] += 1
            else:
                packages[src_dst] = 1

            prev_tick = tick

    #visualize_application(route_application)

    return sw_data, flow_data, traffic_data

def connect_switches(net, matrix):
    switches_amount = len(matrix[0])
    switches = []
    for sw_idx in range (1, switches_amount + 1):
        switch_name = "s" + str(sw_idx)
        switches.append(net.addSwitch(switch_name))

    for sw_idx_fix in range(1, switches_amount):
        for sw_idx_tmp in range(sw_idx_fix, switches_amount):
            link_bw = matrix[sw_idx_fix-1][sw_idx_tmp]
            if (link_bw != 0):
                net.addLink(switches[sw_idx_fix-1], switches[sw_idx_tmp], bw = link_bw, loss = 2)

    return switches


def connect_hosts(net, switches, flow_route):
    hosts = []
    host_names = []
    host_idx = 1
    sw_hosts = {}
    for sw_idx in range(len(switches)):
        host_name = "h" + str(host_idx)
        hosts.append(net.addHost(host_name))
        net.addLink(host_name, switches[sw_idx])
        sw_hosts[sw_idx] = host_name
        host_idx += 1
    net.addHost("h0")
    net.addHost("h101")
    net.addLink("h0", switches[0])
    net.addLink("h101", switches[0])
    return hosts, sw_hosts

def parse_ping_info(info):
    rcv = 0
    sent = 0
    words = info.split()
    prev = ""
    first = True
    for word in words:
        if word == 'packets':
            if (first):
                sent = int(prev)
                first = False
            else:
                rcv = int(prev)
        prev = word

    return rcv, sent - rcv

def write_stat(stat):
    with open('/home/mininet/output/fake_link.txt', 'w+') as f:
        for tick in stat:
            f.write(str(tick) + " " + str(stat[tick][0]) + " " +
                    str(stat[tick][1]) + " " + str(stat[tick][2]) +  "\n")


def dos_attack(stop, net):
    evil_host = net.get('h0')
    while True:
        res = evil_host.cmd('hping3 -c 1000000 --faster -d 300 -S  10.0.0.7')
        if stop():
            break

def ddos_attack(net):
    evil_host = net.get('h0')
    ip_to_attack = random.randint(3, 40)

    rand_time_loop=random.uniform(1,3)
    try:
        res = evil_host.cmd(("hping3 -S -V -i u1 -c 30000 --rand-source 10.0.0.%s" % (ip_to_attack)))
        threading.Timer(rand_time_loop, ddos_attack, args=(net)).start()
    except:
        print("Failed")

def switch_black_hole(stop, net):
    while True:
        evil_host = net.get('h0')
        evil_host.cmd('sudo ovs-ofctl add-flow s16 priority=65535,idle_timeout=0,actions=drop')
        evil_host.cmd('sudo ovs-ofctl add-flow s10 priority=65535,idle_timeout=0,actions=drop')
        evil_host.cmd('sudo ovs-ofctl add-flow s27 priority=65535,idle_timeout=0,actions=drop')
        evil_host.cmd('sudo ovs-ofctl add-flow s36 priority=65535,idle_timeout=0,actions=drop')

        if stop():
            break

def fake_link_injection(net, fake_links):
    time.sleep(50)
    for s1, s2 in fake_links:
        net.configLinkStatus(s1, s2, 'down')

    print("!!!!Links down!!!!!")


def generate_fake_links(net):
    fake_links = set()

    for i in range(18):
        num1, num2 = -1, -1
        while num1 >= num2:
            num1 = random.randint(1, 40)
            num2 = random.randint(1, 40)

        s1 = net.get('s' + str(num1))
        s2 = net.get('s' + str(num2))

        link = net.addLink(s1, s2, bw = 1000)
        s1.attach(link.intf1)
        s2.attach(link.intf2)

        fake_links.add(('s' + str(num1), 's' + str(num2)))

    return fake_links

def form_requests(net, traffic_data, sw_hosts):
    requests = {}
    for tick in traffic_data:
        requests[tick] = {host : [] for host in sw_hosts.values()}

        for src_dst in traffic_data[tick]:
            packages_to_transmit = src_dst[0]

            src, dst = src_dst
            dst_host = net.get(sw_hosts[dst-1])
            request = ("hping3 -c %d -i u10000 -q -d %d %s" % (packages_to_transmit,
                                                               packages_to_transmit * 10,
                                                               dst_host.IP()))
            requests[tick][sw_hosts[src-1]].append(request)


    return requests

def cpu_count(stop, net, q):
    iters = 0
    cpu = 0
    h = net.get('h101')
    while True:
        cpu += float(h.cmd(proc_usage))
        iters += 1
        if stop():
            q.put(cpu/iters)
            #print(cpu/iters)
            break


def traffic_generator(net, cur_requests, q, offset, generators_amount):
    hosts_amount = len(cur_requests)
    rcv_per_tick = 0
    loss_per_tick = 0
    for host_idx in range (offset, hosts_amount, generators_amount):
        host_name = 'h'+str(host_idx+1)
        src_host = net.get(host_name)
        for request in cur_requests[host_name]:
            res = src_host.cmd(request)
            rcv, loss = parse_ping_info(res)
            #threadLock.acquire()

            rcv_per_tick += rcv
            loss_per_tick += loss

            #threadLock.release()

        cur_requests[host_name] = []
    q.put((rcv_per_tick, loss_per_tick))

def generate_traffic(net, requests):
    ticks_amount = len(requests)+1
    packages_stat = {}
    total_packages_loss = 0
    total_packages_rcv = 0
    tick_times = []

    start_dos_tick = -1#3000
    stop_dos_tick =  -1#4000

    start_black_hole_tick = -1#3000
    stop_black_hole_tick = -1 #4000

    start_fake_link = 3000
    stop_fake_link = 4000

    prc_use = 0

    stop_dos = False
    dos = threading.Thread(target=dos_attack, args = (lambda : stop_dos, net))
    ddos = threading.Thread(target=ddos_attack, args = (net))

    stop_black_hole = False
    black_hole = threading.Thread(target = switch_black_hole, args = (lambda : stop_black_hole, net))

    fake_link = None

    q = Queue()
    cpu_q = Queue()
    for tick in requests:
        if (tick == 5001):
            break
        begin = time.time()

        stop_cpu_count = False
        cpu_count_tr = threading.Thread(target=cpu_count, args = (lambda : stop_cpu_count, net, cpu_q))
        cpu_count_tr.start()

        loss_per_tick = 0
        rcv_per_tick = 0

        generators = []
        generators_amount = 40

        for i in range(generators_amount):
            cur_generator = threading.Thread(target=traffic_generator, args=(net, requests[tick], q, i,
                generators_amount))

            generators.append(cur_generator)
            cur_generator.start()

        if tick == start_dos_tick:
            print("Start dos")
            dos.start()

        if (tick == start_black_hole_tick):
            print("Start black hole")
            black_hole.start()

        if (tick == start_fake_link):
            print("Start fake link injection")

            links = generate_fake_links(net)
            print(links)

            fake_link = threading.Thread(target = fake_link_injection, args = (net, links))
            fake_link.start()

        for generator in generators:
            generator.join()


        stop_cpu_count = True
        cpu_count_tr.join()

        while True:
            if q.empty():
                break
            item = q.get()
            rcv_per_tick += item[0]
            loss_per_tick += item[1]
            total_packages_loss += item[1]
            total_packages_rcv += item[0]

        while True:
            if cpu_q.empty():
                break
            prc_use = cpu_q.get()

	if tick == stop_dos_tick:
            stop_dos = True
            dos.join()
            print("Stop dos")

        if tick == stop_black_hole_tick:
            stop_black_hole = True
            black_hole.join()
            print("Stop black hole")

        if tick == stop_fake_link:
            fake_link.join()
            print("Stop fake link injection")

        loss = float(total_packages_loss) / (total_packages_loss + total_packages_rcv)
        rcv =  float(total_packages_rcv) / (total_packages_loss + total_packages_rcv)
        packages_stat[tick] = (rcv_per_tick, loss_per_tick, prc_use)
        end = time.time()
        tick_times.append(end - begin)
        print("-----------------------------------------------")
        print("Sent packages for %d tick:  %d" % (tick, rcv_per_tick + loss_per_tick))
        print("Received: %d packages\tLost: %d packages" % (rcv_per_tick, loss_per_tick))
        print("Total received: %.3f\tTotal loss: %.3f" % (rcv, loss))
        print("CPU usage: %d" % (prc_use))
        print("Sent in %.2fs" % (end - begin))
        print("-----------------------------------------------")

    write_stat(packages_stat)
    with open('/home/mininet/output/tick_times_2.txt', 'w+') as f:
        for cur_time in tick_times:
            f.write(str(cur_time) + ' ')


def create_net(matrix, flow_route, traffic):
    net = Mininet(link=TCLink, host=CPULimitedHost)

    switches_amount = len(matrix[0])
    switches = []
    for sw_idx in range (1, switches_amount + 1):
        switch_name = "s" + str(sw_idx)
        switches.append(net.addSwitch(switch_name))

    switches = connect_switches(net, matrix)
    hosts, sw_hosts = connect_hosts(net, switches, flow_route)

    net.addController('c', controller=RemoteController,ip='0.0.0.0',port=6633)
    net.start()

    requests = form_requests(net, traffic, sw_hosts)

    #dumpNodeConnections(net.hosts)
    #dumpNodeConnections(net.switches)
    generate_traffic(net, requests)
    #CLI(net)

    net.stop()


def main():

    adjacency_matrix, flow_route, traffic = get_data('/home/mininet/net_config/40_nodes_config_0.txt',
                                                     '/home/mininet/net_config/src_dst_flow.txt', 
                                                     '/home/mininet/net_config/traffic_data.txt')

    create_net(adjacency_matrix, flow_route, traffic)


if __name__ == "__main__":
    main()
