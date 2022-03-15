if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843334" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-12 10:26:42 +0200 (Thu, 12 Oct 2017)" );
	script_cve_id( "CVE-2017-9214", "CVE-2017-9263", "CVE-2017-9264", "CVE-2017-9265" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 21:58:00 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openvswitch USN-3450-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openvswitch'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Bhargava Shastry discovered that Open
  vSwitch incorrectly handled certain OFP messages. A remote attacker could
  possibly use this issue to cause Open vSwitch to crash, resulting in a denial of
  service. (CVE-2017-9214) It was discovered that Open vSwitch incorrectly handled
  certain OpenFlow role messages. A remote attacker could possibly use this issue
  to cause Open vSwitch to crash, resulting in a denial of service.
  (CVE-2017-9263) It was discovered that Open vSwitch incorrectly handled certain
  malformed packets. A remote attacker could possibly use this issue to cause Open
  vSwitch to crash, resulting in a denial of service. This issue only affected
  Ubuntu 17.04. (CVE-2017-9264) It was discovered that Open vSwitch incorrectly
  handled group mod OpenFlow messages. A remote attacker could possibly use this
  issue to cause Open vSwitch to crash, resulting in a denial of service.
  (CVE-2017-9265)" );
	script_tag( name: "affected", value: "openvswitch on Ubuntu 17.04,
  Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3450-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3450-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(17\\.04|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "openvswitch-common", ver: "2.6.1-0ubuntu5.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "openvswitch-common", ver: "2.5.2-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

