if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841869" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-01 21:35:34 +0530 (Tue, 01 Jul 2014)" );
	script_cve_id( "CVE-2013-6433", "CVE-2014-0187", "CVE-2014-4167" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for neutron USN-2255-1" );
	script_tag( name: "affected", value: "neutron on Ubuntu 14.04 LTS,
  Ubuntu 13.10" );
	script_tag( name: "insight", value: "Darragh O'Reilly discovered that the Ubuntu packaging for
OpenStack Neutron did not properly set up its sudo configuration. If a
different flaw was found in OpenStack Neutron, this vulnerability could be used
to escalate privileges. (CVE-2013-6433)

Stephen Ma and Christoph Thiel discovered that the openvswitch-agent in
OpenStack Neutron did not properly perform input validation when creating
security group rules when specifying --remote-ip-prefix. A remote
authenticated attacker could exploit this to prevent application of
additional rules. (CVE-2014-0187)

Thiago Martins discovered that OpenStack Neutron would inappropriately
apply SNAT rules to IPv6 subnets when using the L3-agent. A remote
authenticated attacker could exploit this to prevent floating IPv4
addresses from being attached throughout the cloud. (CVE-2014-4167)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2255-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2255-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'neutron'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|13\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-neutron", ver: "1:2014.1-0ubuntu1.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "python-neutron", ver: "1:2013.2.3-0ubuntu1.5", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

