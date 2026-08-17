# -*- mode: ruby -*-
# Sysmon for Linux Malware Lab - Phase 1
# ใช้กับ VMware Workstation Pro + Vagrant บน Windows host

ENV['VAGRANT_DEFAULT_PROVIDER'] = 'vmware_desktop'

Vagrant.configure("2") do |config|

  # box ต้องรองรับ vmware  (bento รองรับทั้ง virtualbox และ vmware)
  config.vm.box = "bento/ubuntu-22.04"
  config.vm.box_check_update = false

  # IP ของ Windows host บนวง host-only
  # VMware ใช้ 192.168.x.1 โดย x ขึ้นกับ VMnet -> ตรวจด้วย ipconfig ก่อน!
  HOST_IP  = "192.168.56.1"
  LOG_PORT = 5514

  config.vm.define "target1" do |node|
    node.vm.hostname     = "target1"
    node.vm.boot_timeout = 600

    # Host-Only network: ท่อส่ง log กลับ host
    node.vm.network "private_network", ip: "192.168.56.11"

    node.vm.provider "vmware_desktop" do |v|
      v.vmx["displayname"] = "lab-target1"
      v.memory = 2048
      v.cpus   = 2
      v.gui    = true            # เห็นหน้าจอ VM ตอนบูต (ดีบักง่าย)

      # ปิดของไม่จำเป็น ลด overhead
      v.vmx["sound.present"]      = "FALSE"
      v.vmx["usb.present"]        = "FALSE"
      v.vmx["mks.enable3d"]       = "FALSE"
      v.vmx["msg.autoAnswer"]     = "TRUE"
   
    end

    node.vm.provision "shell",
      path: "provision/install_sysmon.sh",
      env: { "HOST_IP" => HOST_IP, "LOG_PORT" => LOG_PORT.to_s }

    node.vm.provision "shell", 
    path: "provision/install_tools.sh"
    
    node.vm.provision "shell",
    path: "provision/install_art.sh"

  end

end