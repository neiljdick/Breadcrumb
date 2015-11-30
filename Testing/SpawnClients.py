import subprocess
import struct
import queue
import time

waypoint_index = 0
waypoints =	[	(200, 0.25, 10), 
				(400, 1.0, 60),
				(500, 5, 30),
				(100, 1.67, 15),
				(550, 0.1, 35),
				(150, 0.05, 10),
				(50, 10, 10)
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
			new_client_proc = subprocess.Popen(["/media/veracrypt1/Prototype/Prototype_C/Client/client", "craig", str(port)], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
			try:
			    new_client_proc.communicate(b'CLIENT_INST' + struct.pack("H", proc_queue.qsize()), timeout=0.1)
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