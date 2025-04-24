IMAGE_NAME = "ubuntu/focal64"
N = 2

Vagrant.configure("2") do |config|

    config.vm.provider "virtualbox" do |v|
        v.memory = 1024
        v.cpus = 1
    end

    config.vm.define "bmv2-1" do |switch|
        switch.vm.box = "viniciussimao/bmv2-p4"
        switch.vm.box_version = "01"
        switch.vm.hostname = "bmv2-1"
        
        #management network (IP - 192.168.56.200)
        switch.vm.network "private_network", ip: "192.168.56.200",
            name: "vboxnet0"
        
        #Internal network between host-1 and bmv2 switch1.
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "H1-S1"
        
        #Internal network between bmv2 switches
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "S1-S2"


        switch.vm.provider "virtualbox" do |v|
            v.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
            v.customize ["modifyvm", :id, "--nicpromisc4", "allow-all"]
        end

        switch.vm.provision "ansible" do |ansible| 
            ansible.playbook = "switch-setup/switch-playbook-1.yml"
        end
    end

    config.vm.define "bmv2-2" do |switch|
        switch.vm.box = "viniciussimao/bmv2-p4"
        switch.vm.box_version = "01"
        switch.vm.hostname = "bmv2-2"
        
        #management network (IP - 192.168.56.201)
        switch.vm.network "private_network", ip: "192.168.56.201",
            name: "vboxnet0"
        
        #Internal network between bmv2 switches
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "S1-S2"

	#Internal network between bmv2 switches
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "S2-S3"


        switch.vm.provider "virtualbox" do |v|
            v.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
            v.customize ["modifyvm", :id, "--nicpromisc4", "allow-all"]
        end

        switch.vm.provision "ansible" do |ansible| 
            ansible.playbook = "switch-setup/switch-playbook-2.yml"
        end
    end

    config.vm.define "bmv2-3" do |switch|
        switch.vm.box = "viniciussimao/bmv2-p4"
        switch.vm.box_version = "01"
        switch.vm.hostname = "bmv2-3"
        
        #management network (IP - 192.168.56.202)
        switch.vm.network "private_network", ip: "192.168.56.202",
            name: "vboxnet0"
        
        #Internal network between bmv2 switches
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "S2-S3"
        
        #Internal network between bmv2 switch3 and host-2.
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "S3-H2"
        
        #Internal network between bmv2 switch3 and c-plane.
        switch.vm.network "private_network", auto_config: false,
            virtualbox__intnet: "S3-CP"

        switch.vm.provider "virtualbox" do |v|
            v.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
            v.customize ["modifyvm", :id, "--nicpromisc4", "allow-all"]
            v.customize ["modifyvm", :id, "--nicpromisc5", "allow-all"]
        end
        
        switch.vm.provision "ansible" do |ansible| 
            ansible.playbook = "switch-setup/switch-playbook-2.yml"
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
            virtualbox__intnet: "S3-H2"
        h.vm.provision "ansible" do |ansible| 
            ansible.playbook = "host-setup/host2-playbook.yml"
        end
    end

    config.vm.define "c-plane" do |h|
        h.vm.box = "viniciussimao/bmv2-p4"
        h.vm.box_version = "01"
        h.vm.hostname = "c-plane"
        
	# Redirecionamento de portas
    	h.vm.network "forwarded_port", guest: 9090, host: 9090  # Prometheus
    	h.vm.network "forwarded_port", guest: 3000, host: 3000  # Grafana
	h.vm.network "forwarded_port", guest: 8000, host: 8000	# Metrics FP
	h.vm.network "forwarded_port", guest: 8000, host: 8001  # Metrics FS
	    h.vm.network "private_network", ip: "192.168.50.13", mac: "0800279ac3d7",
            virtualbox__intnet: "S3-CP"
        h.vm.provision "ansible" do |ansible| 
            ansible.playbook = "host-setup/cplane-playbook.yml"
        end
    end

end
