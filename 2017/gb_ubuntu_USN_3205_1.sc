if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843059" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-22 05:51:05 +0100 (Wed, 22 Feb 2017)" );
	script_cve_id( "CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929", "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342", "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for tcpdump USN-3205-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tcpdump'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that tcpdump incorrectly handled certain packets. A
remote attacker could use this issue to cause tcpdump to crash, resulting
in a denial of service, or possibly execute arbitrary code.

In the default installation, attackers would be isolated by the tcpdump
AppArmor profile." );
	script_tag( name: "affected", value: "tcpdump on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3205-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3205-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|12\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "tcpdump", ver: "4.9.0-1ubuntu1~ubuntu14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "tcpdump", ver: "4.9.0-1ubuntu1~ubuntu16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "tcpdump", ver: "4.9.0-1ubuntu1~ubuntu12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "tcpdump", ver: "4.9.0-1ubuntu1~ubuntu16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

