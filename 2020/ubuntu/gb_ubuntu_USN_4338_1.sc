if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844400" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2020-11958" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 02:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-23 03:00:27 +0000 (Thu, 23 Apr 2020)" );
	script_name( "Ubuntu: Security Advisory for re2c (USN-4338-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.10" );
	script_xref( name: "USN", value: "4338-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-April/005401.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 're2c'
  package(s) announced via the USN-4338-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Agostino Sarubbo discovered that re2c incorrectly handled certain files.
An attacker could possibly use this issue to execute arbitrary code." );
	script_tag( name: "affected", value: "'re2c' package(s) on Ubuntu 19.10." );
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
report = "";
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "re2c", ver: "1.2.1-1ubuntu0.1", rls: "UBUNTU19.10" ) )){
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
	exit( 0 );
}
exit( 0 );

