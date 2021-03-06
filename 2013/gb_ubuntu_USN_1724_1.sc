if(description){
	script_tag( name: "affected", value: "openjdk-7 on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit these
  to cause a denial of service. (CVE-2012-1541, CVE-2012-3342, CVE-2013-0351,
  CVE-2013-0419, CVE-2013-0423, CVE-2013-0446, CVE-2012-3213, CVE-2013-0425,
  CVE-2013-0426, CVE-2013-0428, CVE-2013-0429, CVE-2013-0430, CVE-2013-0441,
  CVE-2013-0442, CVE-2013-0445, CVE-2013-0450, CVE-2013-1475, CVE-2013-1476,
  CVE-2013-1478, CVE-2013-1480)

  Vulnerabilities were discovered in the OpenJDK JRE related to information
  disclosure. (CVE-2013-0409, CVE-2013-0434, CVE-2013-0438)

  Several data integrity vulnerabilities were discovered in the OpenJDK JRE.
  (CVE-2013-0424, CVE-2013-0427, CVE-2013-0433, CVE-2013-1473)

  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure and data integrity. (CVE-2013-0432, CVE-2013-0435,
  CVE-2013-0443)

  A vulnerability was discovered in the OpenJDK JRE related to availability.
  An attacker could exploit this to cause a denial of service.
  (CVE-2013-0440)

  A vulnerability was discovered in the OpenJDK JRE related to information
  disclosure and data integrity. An attacker could exploit this to cause a
  denial of service. This issue only affected Ubuntu 12.10. (CVE-2013-0444)

  A data integrity vulnerability was discovered in the OpenJDK JRE. This
  issue only affected Ubuntu 12.10. (CVE-2013-0448)

  An information disclosure vulnerability was discovered in the OpenJDK JRE.
  This issue only affected Ubuntu 12.10. (CVE-2013-0449)

  A vulnerability was discovered in the OpenJDK JRE related to information
  disclosure and data integrity. An attacker could exploit this to cause a
  denial of service. This issue did not affect Ubuntu 12.10. (CVE-2013-1481)" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1724-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841310" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-15 11:22:47 +0530 (Fri, 15 Feb 2013)" );
	script_cve_id( "CVE-2012-1541", "CVE-2012-3342", "CVE-2013-0351", "CVE-2013-0419", "CVE-2013-0423", "CVE-2013-0446", "CVE-2012-3213", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0430", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0445", "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-0409", "CVE-2013-0434", "CVE-2013-0438", "CVE-2013-0424", "CVE-2013-0427", "CVE-2013-0433", "CVE-2013-1473", "CVE-2013-0432", "CVE-2013-0435", "CVE-2013-0443", "CVE-2013-0440", "CVE-2013-0444", "CVE-2013-0448", "CVE-2013-0449", "CVE-2013-1481" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1724-1" );
	script_name( "Ubuntu Update for openjdk-7 USN-1724-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b27-1.12.1-2ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm", ver: "6b27-1.12.1-2ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b27-1.12.1-2ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b27-1.12.1-2ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b27-1.12.1-2ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b27-1.12.1-2ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b27-1.12.1-2ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm", ver: "6b27-1.12.1-2ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b27-1.12.1-2ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b27-1.12.1-2ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b27-1.12.1-2ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b27-1.12.1-2ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b27-1.12.1-2ubuntu0.10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b27-1.12.1-2ubuntu0.10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b27-1.12.1-2ubuntu0.10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b27-1.12.1-2ubuntu0.10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b27-1.12.1-2ubuntu0.10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm", ver: "7u13-2.3.6-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre", ver: "7u13-2.3.6-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless", ver: "7u13-2.3.6-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u13-2.3.6-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero", ver: "7u13-2.3.6-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

