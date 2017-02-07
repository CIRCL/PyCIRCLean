#!/usr/bin/env python3

# Ubuntu: config changes needed
# disable automount of usbstick
# 1) install dconf-editor
# 2) go to org.gnome.desktop.media-handling
#    --> automount -> false
#    --> automount-open -> false

# The tools needed:
# - pmount

# Please install the following in Python
# - pyudev (Python 3)

import itertools
import os

from pyudev import Context
from pyudev import Monitor
from pyudev import MonitorObserver


# list of connected USB devices
usblist = []

def device_connected_event(observer,device):
  # global is needed: this function runs in a separate thread!
  global usblist
  
  if device.action != "add":
    # only allow the event "add" not any other - we need 2 sticks to perform a clean
    print("do not remove the USB devices until done next time!")
    usblist = []
    
  else:
    # subsystem == block means the node will have a /dev/sdXX path - simply put ;)
    if device.subsystem == "block":# and lastdevid != "":
      
      # if the device has partitions and hence the device is not already a partition
      if len([d for d in device.children]) > 0:
        print ("{0} added to the list".format(device.device_node))
        usblist.append(device)


if __name__=="__main__":
  
  context = Context()
  monitor = Monitor.from_netlink(context)
  
  # Start the observer thread
  observer = MonitorObserver(monitor, device_connected_event)
  observer.start()
  
  while(True):
    
    # Once 2 two devices have been found
    if len(usblist) >= 2:# 
      # we do not need to continue watching for partitions anymore so we can stop the monitoring
      observer.stop()
      
      # if a partition choice is needed:
      choiceCountNumber = 0
      
      # remember that the first item in the list is the source USB and the second the destination
      # print a list of the connected devices (USB Sticks) and their partitions
      for item in usblist:
        # we only need and want 2 devices. hence the others do not need to be considered!
        if usblist.index(item) > 1:
          break
          
        print("")
        if usblist.index(item) > 0:
          print("The destination USB Stick {0} has the following partitions:".format(item.device_node))
        else:
          print("The source USB Stick ({0}) has the following partitions:".format(item.device_node))
        
        # as generators do not have an index number, an artificial index is needed
        #  - int this case we will use the choiceCountNumber
        
        for child in item.children:
          
          if usblist.index(item) > 0:
            print (" - {0}: {1}".format(choiceCountNumber,child.device_node))
            choiceCountNumber += 1
          else:
            print (" - {0}".format(child.device_node))
      
      
      # in case the second device has more than one partition, the user can choose to which partition
      # they want to save the "cleaned" files
      chosenPartition = 0
      while (choiceCountNumber > 1):
        try:
          chosenPartition = int(input("Choose the partition by number (see above): "))
          # and, of course only alloy numbers within the range in which a partition can be found ;)
          if (chosenPartition < choiceCountNumber and chosenPartition >= 0):
            break
          else:
            print("That's not a valid partition choice")
        except:
          print("That's not a valid option!")
      
      
      # get the chosen device node
      destinationPartitionNode = (next(itertools.islice(usblist[1].children,chosenPartition,None))).device_node
      
      print("The chosen destination partition is: {0}".format(destinationPartitionNode))
      
      
      # pmount will mount the destination usb stick in /media/usbdestination as write only
      os.system("pmount -w {0} {1}".format(destinationPartitionNode,"usbdestination"))
      
      # only the source device will have an iteration over ALL the found partitions
      for partition in usblist[0].children:
        
        # pmount will mount the source usb stick in /media/sourceusb as read only
        os.system("pmount -r {0} {1}".format(partition.device_node,"sourceusb"))
        
        # Copy all the files using pyCirclean here!
        print("do the needed stuff")
        
        
        
        # it is done... so pumount to release the mounted source partition
        os.system("pumount {0}".format(partition.device_node))
      
      # pumount the destination partition
      os.system("pumount {0}".format(destinationPartitionNode))
      
      print("It is now safe to remove the devices")
      
      break
    #'''
    













