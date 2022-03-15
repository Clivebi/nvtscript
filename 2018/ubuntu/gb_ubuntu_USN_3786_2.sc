if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843807" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_cve_id( "CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15857", "CVE-2018-15858", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864", "CVE-2018-15856" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-11-07 06:02:02 +0100 (Wed, 07 Nov 2018)" );
	script_name( "Ubuntu Update for libxkbcommon USN-3786-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(18\\.04 LTS)" );
	script_xref( name: "USN", value: "3786-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3786-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for
the 'libxkbcommon' package(s) announced via the USN-3786-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
is present on the target host." );
	script_tag( name: "insight", value: "USN-3786-1 fixed several vulnerabilities
in libxkbcommon. This update provides the corresponding update for Ubuntu 18.04 LTS.

Original advisory details:

It was discovered that libxkbcommon incorrectly handled certain files.
An attacker could possibly use this issue to cause a denial of
service. (CVE-2018-15853, CVE-2018-15854, CVE-2018-15855, CVE-2018-
15856, CVE-2018-15857, CVE-2018-15858, CVE-2018-15859, CVE-2018-15861,
CVE-2018-15862, CVE-2018-15863, CVE-2018-15864)" );
	script_tag( name: "affected", value: "libxkbcommon on Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libxkbcommon-x11-0", ver: "0.8.0-1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libxkbcommon0", ver: "0.8.0-1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

