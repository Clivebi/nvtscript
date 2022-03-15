docker_test = make_array();
var docker_test;
docker_test["1.0"] = make_array( "title", "1.0 Use a separate partition for containers.", "desc", "It is advisable to create a separate partition for storing Docker files.", "solution", "Create/Use a separate partition for /var/lib/docker mount point." );
docker_test["1.1"] = make_array( "title", "1.1 Use Linux Kernel >= 3.10.", "desc", "A 3.10 Linux kernel is the minimum requirement for Docker.", "solution", "Update to a kernel version >= 3.10." );
docker_test["1.2"] = make_array( "title", "1.2 Use a up to date Docker version.", "desc", "Use an up to date Docker version to avoid security issues.", "solution", "Make sure you are using an up to data version of docker." );
docker_test["1.3"] = make_array( "title", "1.3 Do not use lxc execution driver.", "desc", "Do not run the Docker daemon with the \"lxc\" execution driver.", "solution", "Remove \"--exec-driver=lxc\" from the Docker daemon command line." );
docker_test["1.4"] = make_array( "title", "1.4 Restrict network traffic between containers.", "desc", "Network traffic between containers should be restricted to avoid information disclosure.", "solution", "Use \"--icc=false\" on the Docker daemon command line." );
docker_test["1.5"] = make_array( "title", "1.5 Set the logging level to \"info\".", "desc", "Docker daemon should not run with a Log level higher then \"info\".", "solution", "Use \"info\" as Log level." );
docker_test["1.6"] = make_array( "title", "1.6 Allow Docker to make changes to iptables.", "desc", "Let Docker daemon make changes to iptables automatically to avoid networking misconfiguration", "solution", "Do not use \"--iptables=false\" at the Docker daemon command line." );
docker_test["1.7"] = make_array( "title", "1.7 Do not use insecure registries", "desc", "Do not use insecure registries. Insecure registries can be manipulated. This could result in a possible compromise of the system.", "solution", "Do not use \"--insecure-registry\" at the Docker daemon command line." );
docker_test["1.8"] = make_array( "title", "1.8 Do not use the \"aufs\" storage driver.", "desc", "The \"aufs\" storage driver should not longer be used.", "solution", "Use a different storage driver." );
docker_test["1.9"] = make_array( "title", "1.9 Configure TLS authentication.", "desc", "TLS authentication should be enabled to avoid full access to the Docker daemon.", "solution", "Restrict access to the docker daemon with TLS authentication." );
docker_test["2.0"] = make_array( "title", "2.0 Enable a default ulimit as appropriate.", "desc", "You should enable a default ulimit for the Docker daemon to enforce the ulimit for all containers.", "solution", "Use \"--default-ulimit\" on the Docker daemon command line." );
docker_test["2.1"] = make_array( "title", "2.1 Enable user namespace support.", "desc", "Enable user namespace support to provide additional security for the Docker host system.", "solution", "Enable user namespace support." );
docker_test["2.2"] = make_array( "title", "2.2 Check default cgroup usage.", "desc", "The setting for the \"--cgroup-parent\" option should be left at its default.", "solution", "Do not use \"--cgroup-parent\" at the Docker daemon command line." );
docker_test["2.3"] = make_array( "title", "2.3 Do not increase base device size if not needed.", "desc", "Setting base device size may cause a denial of service by ending up in file system being full.", "solution", "Do not use \"--storage-opt dm.basesize\" at the Docker daemon command line." );
docker_test["2.4"] = make_array( "title", "2.4 Make use of authorization plugins.", "desc", "For greater access control use of authorization plugins should be introduced.", "solution", "Use authorization plugin to manage access to Docker daemon." );
docker_test["2.5"] = make_array( "title", "2.5 Disable legacy registry v1.", "desc", "Docker registry v2 should be used.", "solution", "Use \"--disable-legacy-registry\" on the Docker daemon command line." );
docker_test["2.6"] = make_array( "title", "2.6 Enable live restore.", "desc", "You should use the \"--live-restore\" option to get support for daemon-less containers in docker.", "solution", "Use \"--live-restore\" on the Docker daemon command line." );
docker_test["2.7"] = make_array( "title", "2.7 Do not use Userland Proxy", "desc", "Where hairpin NAT is available Userland Proxy should be disabled.", "solution", "Use \"--userland-proxy=false\" on the Docker daemon command line." );
docker_test["2.8"] = make_array( "title", "2.8 docker.service file ownership must set to root:root", "desc", "The \"docker.service\" file contains sensitive data and should therefore owned by root:root", "solution", "Change ownership to roo:root" );
docker_test["2.9"] = make_array( "title", "2.9 docker.service file permissions must set to 644 or more restrictive.", "desc", "The \"docker.service\" file contains sensitive data and should therefore only writeable by root.", "solution", "Change permissions to 644 or more restrictive." );
docker_test["3.0"] = make_array( "title", "3.0 docker.socket file ownership must set to root:root", "desc", "docker.socket file contains sensitive data and should therefore owned by root:root", "solution", "Change ownership to roo:root" );
docker_test["3.1"] = make_array( "title", "3.1 docker.socket file permissions must set to 644 or more restrictive.", "desc", "docker.socket file contains sensitive data and should therefore only writeable by root.", "solution", "Change permissions to 644 or more restrictive." );
docker_test["3.2"] = make_array( "title", "3.2 /etc/docker directory ownership must set to root:root.", "desc", "/etc/docker contains sensitive data and should therefore owned by root:root", "solution", "Change ownership to roo:root" );
docker_test["3.3"] = make_array( "title", "3.3 /etc/docker directory permissions must set to 755 or more restrictive", "desc", "/etc/docker contains sensitive data and should therefore only writeable by root.", "solution", "Change permissions to 644 or more restrictive." );
docker_test["3.4"] = make_array( "title", "3.4 Docker socket file ownership must set to root:docker.", "desc", "Docker socket file should be owned by root:docker.", "solution", "Change ownership of Docker socket file to root:docker" );
docker_test["3.5"] = make_array( "title", "3.5 Docker socket file permissions must set to 660 or more restrictive.", "desc", "Docker socket file contains sensitive data and should therefore only writeable by root.", "solution", "Change permissions to 644 or more restrictive." );
docker_test["3.6"] = make_array( "title", "3.6 Do not use user root for container.", "desc", "For best practice do not run containers as root.", "solution", "Run container with non root user." );
docker_test["3.7"] = make_array( "title", "3.7 Use HEALTHCHECK for the container image.", "desc", "Add HEALTHCHECK to the container image to enhance availability.", "solution", "Rebuild your container image with HEALTHCHECK instructions." );
docker_test["3.8"] = make_array( "title", "3.8 Do not use privileged containers.", "desc", "Using \"--privileged\" on the Docker Daemon command line gives all Linux Kernel Capabilities to the container and should therefore not used.", "solution", "Do not use \"--privileged\" when starting a container." );
docker_test["3.9"] = make_array( "title", "3.9 Sensitive host system directories should not be mounted in containers.", "desc", "Sensitive host system directories such as /bin, /sbin, /etc, ... should not be mounted in containers, Epecially not in RW mode.", "solution", "Do not mount sensitive host system directories in containers." );
docker_test["4.0"] = make_array( "title", "4.0 Do not run sshd within containers", "desc", "Running SSH within the container increases the complexity of security management.", "solution", "Disable sshd within containers." );
docker_test["4.1"] = make_array( "title", "4.1 Container ports mapped to a privileged port.", "desc", "Do not map privileged ports within containers.", "solution", "Do not map the container ports to privileged host ports when starting a container." );
docker_test["4.2"] = make_array( "title", "4.2 Do not skip placing the container inside a separate network stack.", "desc", "When using \"--net=host\" Docker not containerize the containers networking. This is potentially dangerous.", "solution", "Do not use \"--net=host\" when starting a container." );
docker_test["4.3"] = make_array( "title", "4.3 Use memory limit for container.", "desc", "A container can use all of the memory on the host. This could lead in denial of service arising from one container consuming all of the hosts memory.", "solution", "Use memory limit for containers." );
docker_test["4.4"] = make_array( "title", "4.4 Use CPU priority for container.", "desc", "Use CPU sharing to allow to prioritize one container over the other and forbids the lower priority container to claim CPU resources more often.", "solution", "Use CPU sharing." );
docker_test["4.5"] = make_array( "title", "4.5 Containers root filesystem should mounted as read only.", "desc", "Writes to the root filesystem should be avoided.", "solution", "Use \"--read-only\" when starting a container." );
docker_test["4.6"] = make_array( "title", "4.6 Bind incoming container traffic to a specific host interface.", "desc", "Avoid that a container accept incoming connections on any interface.", "solution", "Bind the container port to a specific host interface." );
docker_test["4.7"] = make_array( "title", "4.7 Set the \"on-failure\" container restart policy to 5 or less.", "desc", "Set the maximum restart attempts to 5 or less to avoid denial of service of the host.", "solution", "Set the MaximumRetryCount to 5 or less." );
docker_test["4.8"] = make_array( "title", "4.8 Isolate the containers from the hosts process namespace.", "desc", "Sharing the hosts process namespace breaks process level isolation between the host and the containers.", "solution", "Do not use \"--pid=host\" when starting a container." );
docker_test["4.9"] = make_array( "title", "4.9 Isolate the containers from the hosts IPC namespace.", "desc", "Sharing the hosts IPC namespace breaks IPC level isolation between the host and the containers.", "solution", "Do not use \"--ipc=host\" when starting a container." );
docker_test["5.0"] = make_array( "title", "5.0 Do not use propagation mode \"shared\" for mounts.", "desc", "A \"shared\" mount can be mounted and changed by any othercontainer", "solution", "Do not mount volumes in shared mode propagation" );
docker_test["5.1"] = make_array( "title", "5.1 Isolate the containers from the hosts UTS namespace.", "desc", "When sharing the hosts UTS namespace a container can change the hostname of the host.", "solution", "Do not use \"--uts=host\" when starting a container." );
docker_test["5.2"] = make_array( "title", "5.2 Do not disable default seccomp profile.", "desc", "The default seccomp profile should not be disabled to improvise application security.", "solution", "Do not run containers without any seccomp profiles." );
docker_test["5.3"] = make_array( "title", "5.3 Confirm cgroup usage.", "desc", "Use cgroup. to ensure that containers are running under defined cgroups.", "solution", "Do not use \"--cgroup-parent\" when starting a container." );
docker_test["5.4"] = make_array( "title", "5.4 Set no-new-privileges for Container.", "desc", "Restrict the container from acquiring additional privileges via suid or sgid bits.", "solution", "Use \"--security-opt=no-new-privilege\" when starting a container." );
docker_test["5.5"] = make_array( "title", "5.5 Do not share the hosts user namespaces.", "desc", "Sharing the use namespaces with the container does not isolate users on the host with users on the containers.", "solution", "Do not share user namespaces between host and containers." );
docker_test["5.6"] = make_array( "title", "5.6 Docker socket must not mount inside any containers.", "desc", "The docker socket (docker.sock) should not be mounted inside a container.", "solution", "Make sure that no containers mount docker.sock as a volume." );
docker_test["5.7"] = make_array( "title", "5.7 Avoid image sprawl.", "desc", "The number of containers should not be to large.", "solution", "Remove unused images." );
docker_test["5.8"] = make_array( "title", "5.8 Avoid container sprawl.", "desc", "The number of containers on the same host should not be to large.", "solution", "Clean up the containers that are not needed." );
func docker_test_1_0(  ){
	var id, value;
	id = "1.0";
	value = docker_run_cmd( cmd: "grep /var/lib/docker /etc/fstab" );
	if( value && ContainsString( value, "/var/lib/docker" ) ) {
		docker_test_set_success( id: id );
	}
	else {
		docker_test_set_failed( id: id, reason: "/var/lib/docker seems not to be mounted on a separate partition.\n" );
	}
}
func docker_test_1_1(  ){
	id = "1.1";
	var id, value;
	if( value = get_kb_item( "Host/running_kernel_version" ) ){
		if(value && IsMatchRegexp( value, "^[0-9.]+" )){
			parts = split( buffer: value, sep: ".", keep: FALSE );
			ver = parts[0] + "." + parts[1];
			if( version_is_less( version: ver, test_version: "3.10" ) ) {
				docker_test_set_failed( id: id, reason: "Kernel version \"" + value + "\" is < 3.10.\n" );
			}
			else {
				docker_test_set_success( id: id, reason: "Kernel version is: " + value + ".\n" );
			}
		}
	}
	else {
		docker_test_set_error( id: id, reason: "Unable to read kernel version." );
	}
}
func docker_test_1_2(  ){
	var id, version, min_version, value;
	id = "1.2";
	if( version = get_kb_item( "docker/version" ) ){
		min_version = get_minimum_docker_test_version();
		if( min_version ){
			if( version_is_less( version: version, test_version: min_version ) ) {
				docker_test_set_failed( id: id, reason: "Docker version \"" + version + "\" is older then min version \"" + min_version + "\"\n" );
			}
			else {
				docker_test_set_success( id: id, reason: "Docker version is: " + version + "\n" );
			}
		}
		else {
			docker_test_set_error( id: id, reason: "Unable to get minimum docker version." );
		}
	}
	else {
		docker_test_set_error( id: id, reason: "Unable to get docker version." );
	}
}
func docker_test_1_3(  ){
	var id, value;
	id = "1.3";
	if(!ContainsString( get_docker_help_banner(), "--exec-driver" )){
		docker_test_set_skipped( id: id, reason: "\"--exec-driver\" not supported by tested Docker version." );
		return;
	}
	if( ContainsString( get_docker_cmd(), "lxc" ) && ContainsString( get_docker_cmd(), "--exec-driver" ) ) {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running with lxc execution driver.\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is not running with lxc execution driver.\n" );
	}
}
func docker_test_1_4(  ){
	var id, value, affected_containers;
	id = "1.4";
	if(!ContainsString( get_docker_help_banner(), "--icc" )){
		docker_test_set_skipped( id: id, reason: "\"--icc\" not supported by tested Docker version." );
		return;
	}
	if( !IsMatchRegexp( tolower( get_docker_cmd() ), "--icc=(false|0)" ) ) {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is not running with --icc set to \"false\".\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running with --icc set to \"false\".\n" );
	}
}
func docker_test_1_5(  ){
	var id, value;
	id = "1.5";
	if(!ContainsString( get_docker_help_banner(), "--log-level" )){
		docker_test_set_skipped( id: id, reason: "\"--log-level\" not supported by tested Docker version." );
		return;
	}
	if( !ContainsString( get_docker_cmd(), "--log-level" ) ) {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running with default Log level \"info\"." );
	}
	else {
		if(ContainsString( get_docker_cmd(), "log-level" )){
			l = eregmatch( pattern: "log-level=[\'\"]*(debug|info|warn|error|fatal)", string: get_docker_cmd() );
			if( !isnull( l[1] ) ){
				if( IsMatchRegexp( l[1], "(debug|warn|error|fatal)" ) ) {
					docker_test_set_failed( id: id, reason: "Log level \"" + l[1] + "\" is higher then \"info\".\n" );
				}
				else {
					docker_test_set_success( id: id, reason: "Log level is set to \"info\"" );
				}
			}
			else {
				docker_test_set_error( id: id, reason: "Unknown log-level. Value: " + get_docker_cmd() );
			}
		}
	}
}
func docker_test_1_6(  ){
	var id, value;
	id = "1.6";
	if(!ContainsString( get_docker_help_banner(), "--iptables" )){
		docker_test_set_skipped( id: id, reason: "\"--iptables\" not supported by tested Docker version." );
		return;
	}
	if( !ContainsString( get_docker_cmd(), "--iptables" ) ) {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is not running with --iptables set to false." );
	}
	else {
		s = eregmatch( pattern: "iptables=(0|false)", string: tolower( get_docker_cmd() ) );
		if( isnull( s[1] ) ) {
			docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is not running with \"--iptables\" set to false." );
		}
		else {
			docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--iptables\" set to false.\n" );
		}
	}
}
func docker_test_1_7(  ){
	var id, value;
	id = "1.7";
	if(!ContainsString( get_docker_help_banner(), "--insecure-registry" )){
		docker_test_set_skipped( id: id, reason: "\"--insecure-registry\" not supported by tested Docker version." );
		return;
	}
	if( !ContainsString( get_docker_cmd(), "--insecure-registry" ) ) {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running without \"--insecure-registry\".\n" );
	}
	else {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--insecure-registry\".\n" );
	}
}
func docker_test_1_8(  ){
	var id, value;
	id = "1.8";
	s = eregmatch( pattern: "Storage Driver: ([^ \r\n]+)", string: get_docker_info() );
	if( isnull( s[1] ) ) {
		docker_test_set_error( id: id, reason: "Could not read \"Storage Driver\" from \"docker info\" output." );
	}
	else {
		if( chomp( s[1] ) == "aufs" ) {
			docker_test_set_failed( id: id, reason: "According to \"docker info\" the storage driver \"aufs\" is used.\n" );
		}
		else {
			docker_test_set_success( id: id, reason: "According to \"docker info\" the storage driver \"" + s[1] + "\" is used.\n" );
		}
	}
}
func docker_test_1_9(  ){
	var id, value;
	id = "1.9";
	if(!ContainsString( get_docker_help_banner(), "--host" )){
		docker_test_set_skipped( id: id, reason: "\"--host\" not supported by tested Docker version." );
		return;
	}
	if(!ContainsString( get_docker_help_banner(), "--tlsverify" ) || !ContainsString( get_docker_help_banner(), "--tlskey" )){
		docker_test_set_skipped( id: id, reason: "\"--tlsverify/--tlskey\" not supported by tested Docker version." );
		return;
	}
	if( IsMatchRegexp( get_docker_cmd(), "--host\\s*(tcp|unix|udp)://" ) ){
		if( !ContainsString( get_docker_cmd(), "tlsverify" ) || !ContainsString( get_docker_cmd(), "tlskey" ) ) {
			docker_test_set_failed( id: id, reason: "According to the Docker command line, the Docker daemon is missing \"--tlsverify\" and/or \"--tlskey\".\n" );
		}
		else {
			docker_test_set_success( id: id, reason: "According to the Docker command line, the Docker daemon is using TLS authentication" );
		}
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, the Docker daemon did not bind to another IP/Port or a Unix socket." );
	}
}
func docker_test_2_0(  ){
	var id, value;
	id = "2.0";
	if(!ContainsString( get_docker_help_banner(), "--default-ulimit" )){
		docker_test_set_skipped( id: id, reason: "\"--default-ulimit\" not supported by tested Docker version." );
		return;
	}
	if( !ContainsString( get_docker_cmd(), "--default-ulimit" ) ) {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running without \"--default-ulimit\".\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--default-ulimit\".\n" );
	}
}
func docker_test_2_1(  ){
	var docker_running_containers, id, affected_containers, cmd, value, _container;
	docker_running_containers = get_docker_running_containers();
	id = "2.1";
	if( docker_running_containers ){
		if( ContainsString( get_docker_cmd(), "--userns-remap" ) ) {
			docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--userns-remap\".\n" );
		}
		else {
			affected_containers = "";
			for _container in docker_running_containers {
				cmd = "ps -p `docker inspect --format \"{{ .State.Pid }}\" " + docker_truncate_id( _container["id"] ) + "` -o user,pid --no-header";
				value = docker_run_cmd( cmd: cmd );
				if(value && ContainsString( value, "root" )){
					test_2_1_failed = TRUE;
					affected_containers += "ID=" + docker_truncate_id( _container["id"] ) + ", Name=" + _container["name"] + "\t-\tuser, pid = " + value + "\n";
				}
			}
			if( test_2_1_failed ) {
				docker_test_set_failed( id: id, reason: "The following container processes running as root:\n\n" + affected_containers + "\n" );
			}
			else {
				docker_test_set_success( id: id, reason: "No container process is running as root." );
			}
		}
	}
	else {
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
	}
}
func docker_test_2_2(  ){
	var id, value;
	id = "2.2";
	if(!ContainsString( get_docker_help_banner(), "--cgroup-parent" )){
		docker_test_set_skipped( id: id, reason: "\"--cgroup-parent\" not supported by tested Docker version." );
		return;
	}
	if( ContainsString( get_docker_cmd(), "--cgroup-parent" ) ) {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--cgroup-parent\".\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running without \"--cgroup-parent\".\n" );
	}
}
func docker_test_2_3(  ){
	var id, value;
	id = "2.3";
	if(!ContainsString( get_docker_help_banner(), "--storage-opt" )){
		docker_test_set_skipped( id: id, reason: "\"--storage-opt\" not supported by tested Docker version." );
		return;
	}
	if( ContainsString( get_docker_cmd(), "--storage-opt dm.basesize" ) ) {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--storage-opt dm.basesize\".\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running without \"--storage-opt dm.basesize\".\n" );
	}
}
func docker_test_2_4(  ){
	var id, value;
	id = "2.4";
	if(!ContainsString( get_docker_help_banner(), "--authorization-plugin" )){
		docker_test_set_skipped( id: id, reason: "\"--authorization-plugin\" not supported by tested Docker version." );
		return;
	}
	if( !ContainsString( get_docker_cmd(), "--authorization-plugin" ) ) {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running without \"--authorization-plugin\".\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--authorization-plugin\".\n" );
	}
}
func docker_test_2_5(  ){
	var id, value;
	id = "2.5";
	if(!ContainsString( get_docker_help_banner(), "--disable-legacy-registry" )){
		docker_test_set_skipped( id: id, reason: "\"--disable-legacy-registry\" not supported by tested Docker version." );
		return;
	}
	if( !ContainsString( get_docker_cmd(), "--disable-legacy-registry" ) ) {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running without \"--disable-legacy-registry\".\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--disable-legacy-registry\".\n" );
	}
}
func docker_test_2_6(  ){
	var id, value;
	id = "2.6";
	if(!ContainsString( get_docker_help_banner(), "--live-restore" )){
		docker_test_set_skipped( id: id, reason: "\"--live-restore\" not supported by tested Docker version." );
		return;
	}
	if( !ContainsString( get_docker_cmd(), "--live-restore" ) ) {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running without \"--live-restore\".\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--live-restore\".\n" );
	}
}
func docker_test_2_7(  ){
	var id, value;
	id = "2.7";
	if(!ContainsString( get_docker_help_banner(), "--userland-proxy" )){
		docker_test_set_skipped( id: id, reason: "\"--userland-proxy\" not supported by tested Docker version." );
		return;
	}
	if( IsMatchRegexp( get_docker_cmd(), "--userland-proxy=[\"\']*(false|0)[\"\']*" ) ) {
		docker_test_set_success( id: id, reason: "According to the Docker command line, Docker daemon is running with \"--userland-proxy=false\".\n" );
	}
	else {
		docker_test_set_failed( id: id, reason: "According to the Docker command line, Docker daemon is running without \"--userland-proxy=false\".\n" );
	}
}
func docker_test_2_8(  ){
	var docker_service_file, id, value;
	docker_service_file = get_docker_service_file();
	id = "2.8";
	if( docker_service_file ){
		value = docker_run_cmd( cmd: "stat -c %U:%G " + docker_service_file );
		if( ContainsString( value, "root:root" ) ) {
			docker_test_set_success( id: id, reason: docker_service_file + " is owned by \"root:root\"" );
		}
		else {
			docker_test_set_failed( id: id, reason: docker_service_file + " is owned by \"" + value + "\"" );
		}
	}
	else {
		docker_test_set_skipped( id: id, reason: "Not a systemd system" );
	}
}
func docker_test_2_9(  ){
	var docker_service_file, id, value;
	docker_service_file = get_docker_service_file();
	id = "2.9";
	if( docker_service_file ){
		value = docker_run_cmd( cmd: "stat -c %a " + docker_service_file );
		if( IsMatchRegexp( value, "^[0-6][0-4][0-4]$" ) ) {
			docker_test_set_success( id: id, reason: docker_service_file + " has the following permissions: " + value + "\".\n" );
		}
		else {
			docker_test_set_failed( id: id, reason: docker_service_file + "\" has wrong permissions. Should \"644\" or lower but is: \"" + value + "\".\n" );
		}
	}
	else {
		docker_test_set_skipped( id: id, reason: "Not a systemd system" );
	}
}
func docker_test_3_0(  ){
	var id, docker_service_file, docker_socket, value;
	id = "3.0";
	docker_service_file = get_docker_service_file();
	if(docker_service_file){
		docker_socket = get_docker_socket();
	}
	if( docker_socket ){
		value = docker_run_cmd( cmd: "stat -c %U:%G " + docker_socket );
		if( ContainsString( value, "root:root" ) ) {
			docker_test_set_success( id: id, reason: docker_socket + " is owned by \"root:root\"" );
		}
		else {
			docker_test_set_failed( id: id, reason: docker_socket + " is owned by \"" + value + "\"" );
		}
	}
	else {
		docker_test_set_skipped( id: id, reason: "Not a systemd system" );
	}
}
func docker_test_3_1(  ){
	var id, docker_service_file, docker_socket, value;
	id = "3.1";
	docker_service_file = get_docker_service_file();
	if(docker_service_file){
		docker_socket = get_docker_socket();
	}
	if( docker_socket ){
		value = docker_run_cmd( cmd: "stat -c %a " + docker_socket );
		if( IsMatchRegexp( value, "^[0-6][0-4][0-4]$" ) ) {
			docker_test_set_success( id: id, reason: docker_socket + " has the following permissions: " + value + "\".\n" );
		}
		else {
			docker_test_set_failed( id: id, reason: docker_socket + "\" has wrong permissions. Should \"644\" or lower but is: \"" + value + "\".\n" );
		}
	}
	else {
		docker_test_set_skipped( id: id, reason: "Not a systemd system" );
	}
}
func docker_test_3_2(  ){
	var id, value;
	id = "3.2";
	value = docker_run_cmd( cmd: "stat -c %U:%G /etc/docker" );
	if( ContainsString( value, "root:root" ) ) {
		docker_test_set_success( id: id, reason: "/etc/docker is owned by \"root:root\"" );
	}
	else {
		docker_test_set_failed( id: id, reason: "/etc/docker is owned by \"" + value + "\"" );
	}
}
func docker_test_3_3(  ){
	var id, value;
	id = "3.3";
	value = docker_run_cmd( cmd: "stat -c %a /etc/docker" );
	if( IsMatchRegexp( value, "^[0-7][0-5][0-5]$" ) ) {
		docker_test_set_success( id: id, reason: "/etc/docker has the following permissions: " + value + "\".\n" );
	}
	else {
		docker_test_set_failed( id: id, reason: "/etc/docker has wrong permissions. Should \"755\" or lower but is: \"" + value + "\".\n" );
	}
}
func docker_test_3_4(  ){
	var id, value;
	id = "3.4";
	value = docker_run_cmd( cmd: "stat -c %U:%G /var/run/docker.sock" );
	if( ContainsString( value, "root:docker" ) ) {
		docker_test_set_success( id: id, reason: "/var/run/docker.sock is owned by \"root:docker\"" );
	}
	else {
		docker_test_set_failed( id: id, reason: "/var/run/docker.sock is owned by \"" + value + "\"" );
	}
}
func docker_test_3_5(  ){
	var id, value;
	id = "3.5";
	value = docker_run_cmd( cmd: "stat -c %a /var/run/docker.sock" );
	if( IsMatchRegexp( value, "^[0-6][0-6]0$" ) ) {
		docker_test_set_success( id: id, reason: "/var/run/docker.sock has the following permissions: " + value + "\".\n" );
	}
	else {
		docker_test_set_failed( id: id, reason: "/var/run/docker.sock has wrong permissions. Should \"644\" or lower but is: \"" + value + "\".\n" );
	}
}
func docker_test_3_6(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "3.6";
	if(!get_docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "Config_User={{.Config.User}}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( chomp( _line ), "Config_User=$" ) || IsMatchRegexp( chomp( _line ), "User=root$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers running as root:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container is running as root.\n" );
	}
}
func docker_test_3_7(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "3.7";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "Healthcheck=" + "{{ range $key, $val := .Config }}{{ if eq $key \"Healthcheck\" }}{{ $val }}{{ end }}{{ end }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "Healthcheck=$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers running without Healthcheck:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "All containers running with Healthcheck.\n" );
	}
}
func docker_test_3_8(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "3.8";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "Privileged={{.HostConfig.Privileged }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "Privileged=true$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers running Privileged:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container is running Privileged.\n" );
	}
}
func docker_test_3_9(  ){
	var docker_running_containers, id, sens_dir, value, affected_containers, lines, _line, _sd;
	docker_running_containers = get_docker_running_containers();
	id = "3.9";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	sens_dirs = make_list( "/etc",
		 "/sbin",
		 "/bin",
		 "/var",
		 "/boot",
		 "/dev",
		 "/sys",
		 "/proc",
		 "/lib",
		 "/lib64",
		 "/",
		 "/usr" );
	value = docker_inspect( inspect: "{{ range $key, $val := . }}" + "{{ if eq $key \"Volumes\" }}{{ range $vol, $path := . }}{{ $path }}{{ \" \" }}{{ end }}{{ end }}" + "{{ if eq $key \"Mounts\" }}{{ range $mount := $val }}{{ $mount.Source }} (RW: {{ $mount.RW}}) {{\" \"}}" + "{{ end }}{{ end }}{{ end }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			for _sd in sens_dirs {
				if(egrep( pattern: _sd + "($| )", string: _line )){
					affected_containers += _line + "\n";
					break;
				}
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers mounting sensitive host system directories:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container mounting sensitive host system directories.\n" );
	}
}
func docker_test_4_0(  ){
	var docker_running_containers, id, affected_containers, _container, value;
	docker_running_containers = get_docker_running_containers();
	id = "4.0";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	affected_containers = "";
	for _container in docker_running_containers {
		value = docker_run_cmd( cmd: "docker exec " + _container["id"] + " ps -el" );
		if(ContainsString( tolower( value ), "sshd" )){
			affected_containers += "Id=" + docker_truncate_id( _container["id"] ) + ", Name=" + _container["name"] + "\n";
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers running a sshd:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container is running a sshd.\n" );
	}
}
func docker_test_4_1(  ){
	var docker_running_containers, id, affected_containers, _container, ports, p, _l, port;
	docker_running_containers = get_docker_running_containers();
	id = "4.1";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	affected_containers = "";
	for _container in docker_running_containers {
		ports = docker_port_values[_container["id"]];
		if(!ports){
			return;
		}
		if(ports && ( ContainsString( ports, "tcp" ) || ContainsString( ports, "udp" ) )){
			p = split( buffer: ports, sep: ",", keep: FALSE );
			for _l in p {
				port = eregmatch( pattern: ":([0-9]+)", string: _l );
				if(!isnull( port[1] )){
					if(int( port[1] ) < int( 1024 )){
						affected_containers += "Id=" + docker_truncate_id( _container["id"] ) + ", Name=" + _container["name"] + ", Ports=" + str_replace( string: ports, find: "\n", replace: " ," ) + "\n";
					}
				}
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers map privileged ports:\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container map privileged ports.\n" );
	}
}
func docker_test_4_2(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "4.2";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "NetworkMode={{ .HostConfig.NetworkMode }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "NetworkMode=host$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers share the hosts network:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container share the hosts network:\n" );
	}
}
func docker_test_4_3(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "4.3";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "Memory_limit=" + "{{ range $key, $val := .Config }}{{ if eq $key \"Memory\" }}{{ $val }}{{ end }}{{ end }}" + "{{ range $key, $val := .HostConfig }}{{ if eq $key \"Memory\" }}{{ $val }}{{ end }}{{ end }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "Memory_limit=0$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers not using memory limits:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "All containers using memory limits.\n" );
	}
}
func docker_test_4_4(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "4.4";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "cpu=" + "{{ range $key, $val := .Config }}{{ if eq $key \"CpuShares\" }}{{ $val }}{{ end }}{{ end }}" + "{{ range $key, $val := .HostConfig }}{{ if eq $key \"CpuShares\" }}{{ $val }}{{ end }}{{ end }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "cpu=(0|1024)$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers not using cpu priorities:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "All containers using cpu priorities.\n" );
	}
}
func docker_test_4_5(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "4.5";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "ReadonlyRootfs=false$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers root filesystem is not mounted read only:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "All containers root filesystems are mounted read only.\n" );
	}
}
func docker_test_4_6(  ){
	var docker_running_containers, id, affected_containers, interfaces, c, p, _l;
	docker_running_containers = get_docker_running_containers();
	id = "4.6";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	affected_containers = "";
	for _container in docker_running_containers {
		interfaces = "";
		c = docker_port_values[_container["id"]];
		if(c && ( ContainsString( c, "tcp" ) || ContainsString( c, "udp" ) )){
			p = split( buffer: c, sep: ",", keep: FALSE );
			for _l in p {
				if(eregmatch( pattern: "0\\.0\\.0\\.0:([0-9]+)", string: _l )){
					interfaces += chomp( _l ) + ", ";
				}
			}
		}
		if(interfaces){
			affected_containers += "ID=" + docker_truncate_id( _container["id"] ) + ", Name=" + _container["name"] + ", " + interfaces + "\n";
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers listen on 0.0.0.0:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No containers listen on 0.0.0.0.\n" );
	}
}
func docker_test_4_7(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line, c;
	docker_running_containers = get_docker_running_containers();
	id = "4.7";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "policy={{.HostConfig.RestartPolicy.Name}},MaximumRetryCount={{.HostConfig.RestartPolicy.MaximumRetryCount}}\"" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if( ContainsString( _line, "policy=always" ) ) {
				affected_containers += _line;
			}
			else {
				if(ContainsString( _line, "policy=on-failure" )){
					c = eregmatch( pattern: "policy=on-failure,MaximumRetryCount=([0-9]+)", string: _line );
					if(!isnull( c[1] )){
						if(int( c[1] ) > int( 5 )){
							affected_containers += _line + "\n";
						}
					}
				}
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers \"RestartPolicy.MaximumRetryCount\" is > 5:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No containers \"RestartPolicy.MaximumRetryCount\" is > 5\n" );
	}
}
func docker_test_4_8(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "4.8";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "PidMode={{.HostConfig.PidMode}}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "PidMode=host$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers \"PidMode\" is set to \"host\"\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No containers \"PidMode\" is set to \"host.\n" );
	}
}
func docker_test_4_9(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "4.9";
	if(!get_docker_running_containers()){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "IpcMode={{.HostConfig.IpcMode}}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "IpcMode=host$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers \"IpcMode\" is set to \"host\"\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No containers \"IpcMode\" is set to \"host.\n" );
	}
}
func docker_test_5_0(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "5.0";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "Propagation={{ range $mount := .Mounts }}{{$mount.Source}} {{ $mount.Propagation }}, {{ end }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "Propagation=.*shared" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers using \"shared\" Propagation:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No containers using \"shared\" Propagation.\n" );
	}
}
func docker_test_5_1(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "5.1";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "UTSMode={{.HostConfig.UTSMode}}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "UTSMode=host" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers using UTSMode \"host\"\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No containers using UTSMode \"host\".\n" );
	}
}
func docker_test_5_2(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "5.2";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "SecurityOpt={{.HostConfig.SecurityOpt }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(IsMatchRegexp( _line, "SecurityOpt=unconfined" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers using seccomp:unconfined\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container is using seccomp:unconfined\n" );
	}
}
func docker_test_5_3(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "5.3";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "CgroupParent={{.HostConfig.CgroupParent}}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(!IsMatchRegexp( _line, "CgroupParent=$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers not using default cgroup:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "All containers using default cgroup.\n" );
	}
}
func docker_test_5_4(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "5.4";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "SecurityOpt={{.HostConfig.SecurityOpt }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(ContainsString( _line, "SecurityOpt=" ) && !ContainsString( _line, "no-new-privileges" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers not using \"no-new-privileges\":\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "All containers using default no-new-privileges.\n" );
	}
}
func docker_test_5_5(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "5.5";
	if(!get_docker_running_containers()){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "UsernsMode={{.HostConfig.UsernsMode }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(!IsMatchRegexp( _line, "UsernsMode=$" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers share the hosts user namespaces:\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container share the hosts user namespaces.\n" );
	}
}
func docker_test_5_6(  ){
	var docker_running_containers, id, value, affected_containers, lines, _line;
	docker_running_containers = get_docker_running_containers();
	id = "5.6";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	value = docker_inspect( inspect: "{{ range $key, $val := . }}" + "{{ if eq $key \"Volumes\" }}{{ range $vol, $path := . }}{{ $path }}{{ \" \" }}{{ end }}{{ end }}" + "{{ if eq $key \"Mounts\" }}{{ range $mount := $val }}{{ $mount.Source }}{{\" \"}}" + "{{ end }}{{ end }}{{ end }}" );
	if(int( value[0] ) < 0){
		docker_test_set_error( id: id, reason: value[1] );
		return;
	}
	affected_containers = "";
	if(int( value[0] ) == 0){
		lines = split( buffer: value[1], keep: FALSE );
		for _line in lines {
			if(ContainsString( _line, "docker.sock" )){
				affected_containers += _line + "\n";
			}
		}
	}
	if( strlen( affected_containers ) > 0 ) {
		docker_test_set_failed( id: id, reason: "The following containers have mounted \"docker.sock\":\n\n" + affected_containers + "\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "No container have mounted \"docker.sock\".\n" );
	}
}
func docker_test_5_7(  ){
	var id, value;
	id = "5.7";
	value = docker_run_cmd( cmd: "docker images -q | sort -u | wc -l | awk \'{print $1}\'" );
	value = int( value );
	if(!value || !IsMatchRegexp( value, "[0-9]+" )){
		docker_test_set_error( id: id, reason: "Could not get image count\n" );
		return;
	}
	if( value > int( 100 ) ) {
		docker_test_set_failed( id: id, reason: "There are currently " + value + " images installed\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "There are currently " + value + " images installed\n" );
	}
}
func docker_test_5_8(  ){
	var docker_running_containers, id, all_containers, _ac, acc, _rc, rcc, diff;
	docker_running_containers = get_docker_running_containers();
	id = "5.8";
	if(!docker_running_containers){
		docker_test_set_skipped( id: id, reason: "No running containers found\n" );
		return;
	}
	all_containers = docker_build_all_containers_array();
	for _ac in all_containers {
		acc++;
	}
	for _rc in docker_running_containers {
		rcc++;
	}
	diff = int( acc - rcc );
	if( int( diff ) > 25 ) {
		docker_test_set_failed( id: id, reason: "There are currently a total of " + acc + " containers, with only " + rcc + " of them currently running\n" );
	}
	else {
		docker_test_set_success( id: id, reason: "There are currently a total of " + acc + " containers, with " + rcc + " of them currently running.\n" );
	}
}

