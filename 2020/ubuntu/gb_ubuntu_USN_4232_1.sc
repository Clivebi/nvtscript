if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844287" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2017-14165", "CVE-2017-14314", "CVE-2017-14504", "CVE-2017-14649", "CVE-2017-14733", "CVE-2017-14994", "CVE-2017-14997", "CVE-2017-15277", "CVE-2017-15930", "CVE-2017-16352", "CVE-2017-16353" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-30 03:15:00 +0000 (Sun, 30 Jun 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 11:03:48 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Ubuntu Update for graphicsmagick USN-4232-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4232-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005260.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'graphicsmagick'
  package(s) announced via the USN-4232-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that GraphicsMagick incorrectly handled certain image files.
An attacker could possibly use this issue to cause a denial of service or other
unspecified impact." );
	script_tag( name: "affected", value: "'graphicsmagick' package(s) on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick", ver: "1.3.23-1ubuntu0.4", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "-q16-12", ver: "1.3.23-1ubuntu0.4", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick-q16-3", ver: "1.3.23-1ubuntu0.4", rls: "UBUNTU16.04 LTS" ) )){
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

