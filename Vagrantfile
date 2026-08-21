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
      # 4096: ทดลองแล้วพบว่า RAM ไม่ใช่สาเหตุของ lineage ขาด (2GB vs 6GB ให้ผล
      # เท่ากันทุกตัวชี้วัด) ส่วนข้อความ "systemd-sysv-generator: Out of memory"
      # เป็น error รวมของ systemd ตอน parse ชื่อ unit T1543.002.service ที่มีจุด
      # ไม่ใช่ RAM หมด (kernel oom-killer = 0 ครั้ง)
      # เลือก 4096 เป็นทางสายกลาง: มี headroom แต่ snapshot ไม่ช้าเท่า 6144
      v.memory = 4096
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

  # ---------------------------------------------------------------- Windows 10
  # เก็บ dataset ฝั่ง Windows เพื่อ merge กับ Linux (แนวทาง B: 6 event ร่วม)
  # รันทีละเครื่อง (RAM จำกัด) - อย่า `vagrant up` พร้อม target1
  #   vagrant up wintarget          # บูตเฉพาะ Windows
  #   vagrant halt wintarget
  # ⚠️ box Windows ใหญ่ ~15-25GB, license eval 180 วัน
  config.vm.define "wintarget", autostart: false do |node|
    node.vm.box          = "gusztavvargadr/windows-10"
    node.vm.boot_timeout = 900
    node.vm.communicator = "winrm"
    # ART download atomics นาน (~1-2GB) -> เพิ่ม timeout กัน WinRM หลุดกลาง provision
    node.winrm.timeout       = 1800
    node.winrm.retry_limit   = 60
    node.winrm.retry_delay   = 10

    node.vm.network "private_network", ip: "192.168.56.21"

    node.vm.provider "vmware_desktop" do |v|
      v.vmx["displayname"] = "lab-wintarget"
      v.memory = 4096
      v.cpus   = 2
      v.gui    = true
      v.vmx["sound.present"] = "FALSE"
      v.vmx["usb.present"]   = "FALSE"
    end

    # ติดตั้ง Sysmon (Windows) + config research + collector agent
    node.vm.provision "shell",
      path: "provision/windows/install_sysmon_win.ps1",
      env: { "HOST_IP" => HOST_IP, "LOG_PORT" => LOG_PORT.to_s }

    # ปิด Defender ก่อน (ไม่งั้นลบ real malware ตอน download) - VM isolated เท่านั้น
    node.vm.provision "shell",
      path: "provision/windows/disable_defender_win.ps1"

    # ติดตั้ง PowerShell + Atomic Red Team (Windows tests)
    node.vm.provision "shell",
      path: "provision/windows/install_art_win.ps1"
  end

end