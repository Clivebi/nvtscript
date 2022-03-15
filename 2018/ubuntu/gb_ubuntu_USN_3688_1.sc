if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843566" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-20 06:05:50 +0200 (Wed, 20 Jun 2018)" );
	script_cve_id( "CVE-2017-7810", "CVE-2017-7826", "CVE-2018-5089", "CVE-2018-5125", "CVE-2018-5150" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for mozjs52 USN-3688-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mozjs52'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple memory safety issues were fixed in Spidermonkey. An attacker
could potentially exploit these to cause a denial of service, or execute
arbitrary code." );
	script_tag( name: "affected", value: "mozjs52 on Ubuntu 18.04 LTS,
  Ubuntu 17.10" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3688-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3688-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(17\\.10|18\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libmozjs-52-0", ver: "52.8.1-0ubuntu0.17.10.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libmozjs-52-0", ver: "52.8.1-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

