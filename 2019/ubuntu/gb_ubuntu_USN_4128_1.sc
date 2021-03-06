if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844170" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-0221", "CVE-2019-0199", "CVE-2019-10072" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-28 21:29:00 +0000 (Tue, 28 May 2019)" );
	script_tag( name: "creation_date", value: "2019-09-11 02:00:49 +0000 (Wed, 11 Sep 2019)" );
	script_name( "Ubuntu Update for tomcat8 USN-4128-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4128-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-September/005109.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat8'
  package(s) announced via the USN-4128-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Tomcat 8 SSI printenv command echoed user
provided data without escaping it. An attacker could possibly use this
issue to perform an XSS attack. (CVE-2019-0221)

It was discovered that Tomcat 8 did not address HTTP/2 connection window
exhaustion on write while addressing CVE-2019-0199. An attacker could
possibly use this issue to cause a denial of service. (CVE-2019-10072)" );
	script_tag( name: "affected", value: "'tomcat8' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.5.39-1ubuntu1~18.04.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "tomcat8", ver: "8.5.39-1ubuntu1~18.04.3", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.0.32-1ubuntu1.10", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "tomcat8", ver: "8.0.32-1ubuntu1.10", rls: "UBUNTU16.04 LTS" ) )){
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

