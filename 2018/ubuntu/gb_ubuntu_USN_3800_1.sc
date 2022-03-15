if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843741" );
	script_version( "2021-06-04T11:00:20+0000" );
	script_cve_id( "CVE-2018-13440", "CVE-2018-17095" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-09 15:08:00 +0000 (Tue, 09 Feb 2021)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:14:05 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for audiofile USN-3800-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	script_xref( name: "USN", value: "3800-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3800-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'audiofile'
  package(s) announced via the USN-3800-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that audiofile incorrectly handled certain files.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2018-13440)

It was discovered that audiofile incorrectly handled certain files.
An attacker could possibly use this issue toexecute arbitrary code.
(CVE-2018-17095)" );
	script_tag( name: "affected", value: "audiofile on Ubuntu 14.04 LTS." );
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
	if(( res = isdpkgvuln( pkg: "audiofile-tools", ver: "0.3.6-2ubuntu0.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libaudiofile1", ver: "0.3.6-2ubuntu0.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

