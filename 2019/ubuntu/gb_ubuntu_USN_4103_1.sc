if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844142" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2019-1020014" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-14 04:15:00 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-08-20 02:00:48 +0000 (Tue, 20 Aug 2019)" );
	script_name( "Ubuntu Update for golang-github-docker-docker-credential-helpers USN-4103-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.04" );
	script_xref( name: "USN", value: "4103-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-August/005075.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-github-docker-docker-credential-helpers'
  package(s) announced via the USN-4103-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jasiel Spelman discovered that a double free existed in docker-credential-
helpers. A local attacker could use this to cause a denial of service
(crash) or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "'golang-github-docker-docker-credential-helpers' package(s) on Ubuntu 19.04." );
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
	if(!isnull( res = isdpkgvuln( pkg: "golang-docker-credential-helpers", ver: "0.6.1-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
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

