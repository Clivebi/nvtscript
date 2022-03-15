if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704409" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-9735" );
	script_name( "Debian Security Advisory DSA 4409-1 (neutron - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-18 00:00:00 +0100 (Mon, 18 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4409.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/neutron" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "neutron on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 2:9.1.1-3+deb9u1.

We recommend that you upgrade your neutron packages." );
	script_tag( name: "summary", value: "Erik Olof Gunnar Andersson discovered that incorrect validation of port
settings in the iptables security group driver of Neutron, the OpenStack
virtual network service, could result in denial of service in a multi
tenant setup." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "neutron-common", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-dhcp-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-l3-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-linuxbridge-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-macvtap-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-metadata-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-metering-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-openvswitch-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-plugin-linuxbridge-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-plugin-nec-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-plugin-openvswitch-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-server", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "neutron-sriov-agent", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-neutron", ver: "2:9.1.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

