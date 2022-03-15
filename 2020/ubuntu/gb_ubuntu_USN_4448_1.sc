if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844527" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-13935", "CVE-2020-1935", "CVE-2020-9484" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 19:19:00 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2020-08-05 03:00:33 +0000 (Wed, 05 Aug 2020)" );
	script_name( "Ubuntu: Security Advisory for tomcat8 (USN-4448-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4448-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-August/005544.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat8'
  package(s) announced via the USN-4448-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Tomcat incorrectly validated the payload length in
a WebSocket frame. A remote attacker could possibly use this issue to cause
Tomcat to hang, resulting in a denial of service. (CVE-2020-13935)

It was discovered that Tomcat incorrectly handled HTTP header parsing. In
certain environments where Tomcat is located behind a reverse proxy, a
remote attacker could possibly use this issue to perform HTTP Request
Smuggling. (CVE-2020-1935)

It was discovered that Tomcat incorrectly handled certain uncommon
PersistenceManager with FileStore configurations. A remote attacker could
possibly use this issue to execute arbitrary code. (CVE-2020-9484)" );
	script_tag( name: "affected", value: "'tomcat8' package(s) on Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.0.32-1ubuntu1.13", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "tomcat8", ver: "8.0.32-1ubuntu1.13", rls: "UBUNTU16.04 LTS" ) )){
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

