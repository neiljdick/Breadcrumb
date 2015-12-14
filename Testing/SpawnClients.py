import subprocess
import struct
import queue
import time

client_num = 0

waypoint_index = 0
waypoints =     [   (40, 0.25, 10),
                    (100, 0.05, 10),
                    (220, 1.0, 10),
                    (160, 5, 10),
                    (20, 1.67, 10),
                    (110, 0.1, 10),
                    (40, 0.05, 10),
                    (180, 10, 10)
                ]

port_min = 16384;
port_max = 65530
port_inc = 5
port = port_min;

proc_queue = queue.Queue()

while waypoint_index < len(waypoints):
	num_clients_target = waypoints[waypoint_index][0]
	interval_between_spawn = waypoints[waypoint_index][1]
	waypoint_remain_time_min = waypoints[waypoint_index][2]

	while (waypoint_remain_time_min > 0):
		if(proc_queue.qsize() < num_clients_target):
			new_client_proc = subprocess.Popen(["/media/veracrypt1/Prototype/Prototype_C/Client/client", ("client_" + str(client_num)), str(port)], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
			client_num += 1
			try:
				new_client_proc.communicate("/connect CLIENT_INST" + str(proc_queue.qsize()) + "\n", timeout=0.1)
				new_client_proc.stdin.flush()
			except Exception:
				pass
			
			proc_queue.put(new_client_proc)
			port += port_inc
			if port > port_max:
				port = port_min
			time.sleep(interval_between_spawn)
		elif(proc_queue.qsize() > num_clients_target):
			if not proc_queue.empty():
				oldest_client_proc = proc_queue.get()
				oldest_client_proc.terminate()
			time.sleep(interval_between_spawn)
		else:
			time.sleep(60)
			waypoint_remain_time_min -= 1
			if waypoint_remain_time_min <= 0:
				break;

	waypoint_index += 1
	if(waypoint_index >= len(waypoints)):
		break

while not proc_queue.empty():
	proc_queue.get().terminate()