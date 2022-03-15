if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842635" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-02-10 06:34:21 +0100 (Wed, 10 Feb 2016)" );
	script_cve_id( "CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 20:13:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for nginx USN-2892-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nginx'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that nginx incorrectly
  handled certain DNS server responses when the resolver is enabled. A remote
  attacker could possibly use this issue to cause nginx to crash, resulting in
  a denial of service. (CVE-2016-0742)

  It was discovered that nginx incorrectly handled CNAME response processing
  when the resolver is enabled. A remote attacker could use this issue to
  cause nginx to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-0746)

  It was discovered that nginx incorrectly handled CNAME resolution when
  the resolver is enabled. A remote attacker could possibly use this issue to
  cause nginx to consume resources, resulting in a denial of service.
  (CVE-2016-0747)" );
	script_tag( name: "affected", value: "nginx on Ubuntu 15.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2892-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2892-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "nginx-core", ver: "1.4.6-1ubuntu3.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.4.6-1ubuntu3.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.4.6-1ubuntu3.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.4.6-1ubuntu3.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-naxsi", ver: "1.4.6-1ubuntu3.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "nginx-core", ver: "1.9.3-1ubuntu1.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.9.3-1ubuntu1.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.9.3-1ubuntu1.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.9.3-1ubuntu1.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

