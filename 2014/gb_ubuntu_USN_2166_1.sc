if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841776" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-15 09:43:16 +0530 (Tue, 15 Apr 2014)" );
	script_cve_id( "CVE-2012-6151", "CVE-2014-2284", "CVE-2014-2285", "CVE-2014-2310" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for net-snmp USN-2166-1" );
	script_tag( name: "affected", value: "net-snmp on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "Ken Farnen discovered that Net-SNMP incorrectly handled AgentX
timeouts. A remote attacker could use this issue to cause the server to crash
or to hang, resulting in a denial of service. (CVE-2012-6151)

It was discovered that the Net-SNMP ICMP-MIB incorrectly validated input. A
remote attacker could use this issue to cause the server to crash,
resulting in a denial of service. This issue only affected Ubuntu 13.10.
(CVE-2014-2284)

Viliam P&#250 &#269 ik discovered that the Net-SNMP perl trap handler incorrectly
handled NULL arguments. A remote attacker could use this issue to cause the
server to crash, resulting in a denial of service. (CVE-2014-2285)

It was discovered that Net-SNMP incorrectly handled AgentX multi-object
requests. A remote attacker could use this issue to cause the server to
hang, resulting in a denial of service. This issue only affected Ubuntu
10.04 LTS, Ubuntu 12.04 LTS and Ubuntu 12.10. (CVE-2014-2310)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2166-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2166-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'net-snmp'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|10\\.04 LTS|13\\.10|12\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libsnmp15", ver: "5.4.3~dfsg-2.4ubuntu1.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libsnmp15", ver: "5.4.2.1~dfsg0ubuntu1-0ubuntu2.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libsnmp30:i386", ver: "5.7.2~dfsg-8ubuntu1.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libsnmp15", ver: "5.4.3~dfsg-2.5ubuntu1.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

