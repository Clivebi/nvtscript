if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1058-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840577" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-02-04 14:19:53 +0100 (Fri, 04 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1058-1" );
	script_cve_id( "CVE-2010-4015" );
	script_name( "Ubuntu Update for PostgreSQL vulnerability USN-1058-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(9\\.10|6\\.06 LTS|10\\.04 LTS|8\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1058-1" );
	script_tag( name: "affected", value: "PostgreSQL vulnerability on Ubuntu 6.06 LTS,
  Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Geoff Keating reported that a buffer overflow exists in the intarray
  module's input function for the query_int type. This could allow an
  attacker to cause a denial of service or possibly execute arbitrary
  code as the postgres user." );
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
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg6", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq5", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-8.4", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client-8.4", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib-8.4", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-server-dev-8.4", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plperl-8.4", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plpython-8.4", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-pltcl-8.4", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc-8.4", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql", ver: "8.4.7-0ubuntu0.9.10", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU6.06 LTS"){
	if(( res = isdpkgvuln( pkg: "libecpg-compat2", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg5", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpgtypes2", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq4", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-8.1", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client-8.1", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib-8.1", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plperl-8.1", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plpython-8.1", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-pltcl-8.1", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-server-dev-8.1", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc-8.1", ver: "8.1.23-0ubuntu0.6.06.1", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg6", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq5", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-8.4", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client-8.4", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib-8.4", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-server-dev-8.4", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plperl-8.4", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plpython-8.4", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-pltcl-8.4", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc-8.4", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql", ver: "8.4.7-0ubuntu0.10.04", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg6", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq5", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-8.3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client-8.3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib-8.3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plperl-8.3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plpython-8.3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-pltcl-8.3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-server-dev-8.3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc-8.3", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql", ver: "8.3.14-0ubuntu8.04", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libecpg6", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpq5", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-8.4", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client-8.4", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib-8.4", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-server-dev-8.4", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plperl-8.4", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-plpython-8.4", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-pltcl-8.4", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-client", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-contrib", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc-8.4", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql-doc", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "postgresql", ver: "8.4.7-0ubuntu0.10.10", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

