if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842091" );
	script_version( "2020-02-04T09:04:16+0000" );
	script_tag( name: "last_modification", value: "2020-02-04 09:04:16 +0000 (Tue, 04 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-02-12 05:28:16 +0100 (Thu, 12 Feb 2015)" );
	script_cve_id( "CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for postgresql-9.4 USN-2499-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql-9.4'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Stephen Frost discovered that PostgreSQL
incorrectly displayed certain values in error messages. An authenticated user
could gain access to seeing certain values, contrary to expected permissions.
(CVE-2014-8161)

Andres Freund, Peter Geoghegan and Noah Misch discovered that PostgreSQL
incorrectly handled buffers in to_char functions. An authenticated attacker
could possibly use this issue to cause PostgreSQL to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2015-0241)

It was discovered that PostgreSQL incorrectly handled memory in the
pgcrypto extension. An authenticated attacker could possibly use this issue
to cause PostgreSQL to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2015-0243)

Emil Lenngren discovered that PostgreSQL incorrectly handled extended
protocol message reading. An authenticated attacker could possibly use this
issue to cause PostgreSQL to crash, resulting in a denial of service, or
possibly inject query messages. (CVE-2015-0244)" );
	script_tag( name: "affected", value: "postgresql-9.4 on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2499-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2499-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS|10\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "postgresql-9.4", ver: "9.4.1-0ubuntu0.14.10", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "postgresql-9.3", ver: "9.3.6-0ubuntu0.14.04", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "postgresql-9.1", ver: "9.1.15-0ubuntu0.12.04", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "postgresql-8.4", ver: "8.4.22-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

