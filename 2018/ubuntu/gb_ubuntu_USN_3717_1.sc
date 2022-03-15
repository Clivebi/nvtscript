if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843594" );
	script_version( "$Revision: 14288 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2018-07-17 05:51:28 +0200 (Tue, 17 Jul 2018)" );
	script_cve_id( "CVE-2015-3218", "CVE-2015-3255", "CVE-2015-4625", "CVE-2018-1116" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for policykit-1 USN-3717-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'policykit-1'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "insight", value: "Tavis Ormandy discovered that PolicyKit
incorrectly handled certain invalid object paths. A local attacker could possibly
use this issue to cause PolicyKit to crash, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS. (CVE-2015-3218)

It was discovered that PolicyKit incorrectly handled certain duplicate
action IDs. A local attacker could use this issue to cause PolicyKit to
crash, resulting in a denial of service, or possibly escalate privileges.
This issue only affected Ubuntu 14.04 LTS. (CVE-2015-3255)

Tavis Ormandy discovered that PolicyKit incorrectly handled duplicate
cookie values. A local attacker could use this issue to cause PolicyKit to
crash, resulting in a denial of service, or possibly escalate privileges.
This issue only affected Ubuntu 14.04 LTS. (CVE-2015-4625)

Matthias Gerstner discovered that PolicyKit incorrectly checked users. A
local attacker could possibly use this issue to cause authentication
dialogs to show up for other users, leading to a denial of service or an
information leak. (CVE-2018-1116)" );
	script_tag( name: "affected", value: "policykit-1 on Ubuntu 18.04 LTS,
  Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3717-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3717-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|18\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libpolkit-backend-1-0", ver: "0.105-4ubuntu3.14.04.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libpolkit-backend-1-0", ver: "0.105-18ubuntu0.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpolkit-backend-1-0", ver: "0.105-20ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpolkit-backend-1-0", ver: "0.105-14.1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

