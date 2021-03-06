if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1637-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841222" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-23 11:53:31 +0530 (Fri, 23 Nov 2012)" );
	script_cve_id( "CVE-2012-2733", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887", "CVE-2012-3439" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "USN", value: "1637-1" );
	script_name( "Ubuntu Update for tomcat6 USN-1637-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1637-1" );
	script_tag( name: "affected", value: "tomcat6 on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the Apache Tomcat HTTP NIO connector incorrectly
  handled header data. A remote attacker could cause a denial of service by
  sending requests with a large amount of header data. (CVE-2012-2733)

  It was discovered that Apache Tomcat incorrectly handled DIGEST
  authentication. A remote attacker could possibly use these flaws to perform
  a replay attack and bypass authentication. (CVE-2012-5885, CVE-2012-5886,
  CVE-2012-5887)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.35-1ubuntu3.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.32-5ubuntu1.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.24-2ubuntu1.11", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

