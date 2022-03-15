if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843986" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-9210" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-25 02:00:30 +0000 (Thu, 25 Apr 2019)" );
	script_name( "Ubuntu Update for advancecomp USN-3936-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.04" );
	script_xref( name: "USN", value: "3936-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-April/004862.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'advancecomp'
  package(s) announced via the USN-3936-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3936-1 fixed a vulnerability in AdvanceCOMP. This update provides
the corresponding update for Ubuntu 19.04.

Original advisory details:

 It was discovered that AdvanceCOMP incorrectly handled certain PNG
 files. An attacker could possibly use this issue to execute arbitrary
 code." );
	script_tag( name: "affected", value: "'advancecomp' package(s) on Ubuntu 19.04." );
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "advancecomp", ver: "2.1-1ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
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

