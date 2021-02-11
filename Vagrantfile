IMAGE_NAME = "ubuntu/focal64"
N = 2

Vagrant.configure("2") do |config|

    config.vm.provider "virtualbox" do |v|
        v.memory = 1024
        v.cpus = 1
    end

    config.vm.define "bmv2" do |switch|
        switch.vm.box = "leandrocdealmeida/bmv2-p4"
        switch.vm.hostname = "bmv2"
        
        #management network (IP - 192.168.56.200)
        switch.vm.network "private_network", ip: "192.168.56.200",
            name: "vboxnet0"
        
        #Internal network between host-1 and bmv2 switch.
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "H1-S1"
        
        #Internal network between bmv2 switch and host-2.
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "H2-S1"

        switch.vm.provision "ansible" do |ansible| 
            ansible.playbook = "switch-setup/switch-playbook.yml"
        end
    end

    config.vm.define "host-1" do |h|
        h.vm.box = IMAGE_NAME
        h.vm.hostname = "host-1"
        h.vm.network "private_network", ip: "192.168.50.11", mac: "080027600c50",
            virtualbox__intnet: "H1-S1"
        h.vm.provision "ansible" do |ansible| 
            ansible.playbook = "host-setup/host1-playbook.yml"
        end
    end

    config.vm.define "host-2" do |h|
        h.vm.box = IMAGE_NAME
        h.vm.hostname = "host-2"
        h.vm.network "private_network", ip: "192.168.50.12", mac: "0800271de027",
            virtualbox__intnet: "H2-S1"
        h.vm.provision "ansible" do |ansible| 
            ansible.playbook = "host-setup/host2-playbook.yml"
        end
    end



end
