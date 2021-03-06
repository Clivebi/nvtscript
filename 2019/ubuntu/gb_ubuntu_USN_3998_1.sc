if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844027" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2018-15587" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-10 07:29:00 +0000 (Mon, 10 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-05-31 02:00:31 +0000 (Fri, 31 May 2019)" );
	script_name( "Ubuntu Update for evolution-data-server USN-3998-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3998-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-May/004927.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'evolution-data-server'
  package(s) announced via the USN-3998-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Marcus Brinkmann discovered that Evolution Data Server did not correctly
interpret the output from GPG when decrypting encrypted messages. Under
certain circumstances, this could result in displaying clear-text portions
of encrypted messages as though they were encrypted." );
	script_tag( name: "affected", value: "'evolution-data-server' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "evolution-data-server", ver: "3.28.5-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "evolution-data-server-common", ver: "3.28.5-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcamel-1.2-61", ver: "3.28.5-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libebackend-1.2-10", ver: "3.28.5-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libedataserver-1.2-23", ver: "3.28.5-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "evolution-data-server", ver: "3.18.5-1ubuntu1.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "evolution-data-server-common", ver: "3.18.5-1ubuntu1.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcamel-1.2-54", ver: "3.18.5-1ubuntu1.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libebackend-1.2-10", ver: "3.18.5-1ubuntu1.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libedataserver-1.2-21", ver: "3.18.5-1ubuntu1.2", rls: "UBUNTU16.04 LTS" ) )){
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

