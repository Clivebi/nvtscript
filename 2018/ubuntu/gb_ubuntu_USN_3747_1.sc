if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843622" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-22 06:45:44 +0200 (Wed, 22 Aug 2018)" );
	script_cve_id( "CVE-2018-2825", "CVE-2018-2826", "CVE-2018-2952", "CVE-2018-2972" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-lts USN-3747-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-lts'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenJDK did not properly validate types in some
situations. An attacker could use this to construct a Java class that could
possibly bypass sandbox restrictions. (CVE-2018-2825, CVE-2018-2826)

It was discovered that the PatternSyntaxException class in OpenJDK did not
properly validate arguments passed to it. An attacker could use this to
potentially construct a class that caused a denial of service (excessive
memory consumption). (CVE-2018-2952)

Daniel Bleichenbacher discovered a vulnerability in the Galois/Counter Mode
(GCM) mode of operation for symmetric block ciphers in OpenJDK. An attacker
could use this to expose sensitive information. (CVE-2018-2972)" );
	script_tag( name: "affected", value: "openjdk-lts on Ubuntu 18.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3747-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3747-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "10.0.2+13-1ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "10.0.2+13-1ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "10.0.2+13-1ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

