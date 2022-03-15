if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843680" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_cve_id( "CVE-2018-14679", "CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-26 11:45:00 +0000 (Mon, 26 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:06:02 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for clamav USN-3728-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	script_xref( name: "USN", value: "3728-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3728-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the USN-3728-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3728-1 fixed several vulnerabilities in libmspack. In Ubuntu 14.04
libmspack is included into ClamAV. This update provides the
corresponding update for Ubuntu 14.04 LTS.

Original advisory details:

Hanno Bck discovered that libmspack incorrectly handled certain CHM
files. An attacker could possibly use this issue to cause a denial of
service. (CVE-2018-14679, CVE-2018-14680)

Jakub Wilk discovered that libmspack incorrectly handled certain KWAJ
files. An attacker could possibly use this issue to execute arbitrary
code. (CVE-2018-14681)

Dmitry Glavatskikh discovered that libmspack incorrectly certain CHM
files. An attacker could possibly use this issue to execute arbitrary
code. (CVE-2018-14682)" );
	script_tag( name: "affected", value: "clamav on Ubuntu 14.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.100.1+dfsg-1ubuntu0.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

