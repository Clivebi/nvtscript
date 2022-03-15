if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841711" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-17 11:40:03 +0530 (Mon, 17 Feb 2014)" );
	script_cve_id( "CVE-2013-1070", "CVE-2013-1069" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Ubuntu Update for maas USN-2105-1" );
	script_tag( name: "affected", value: "maas on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "James Troup discovered that MAAS stored RabbitMQ
authentication credentials in a world-readable file. A local authenticated
user could read this password and potentially gain privileges of other
user accounts. This update restricts the file permissions to prevent
unintended access. (CVE-2013-1070)

Chris Glass discovered that the MAAS API was vulnerable to cross-site
scripting vulnerabilities. With cross-site scripting vulnerabilities,
if a user were tricked into viewing a specially crafted page, a remote
attacker could exploit this to modify the contents, or steal confidential
data, within the same domain. (CVE-2013-1069)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2105-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2105-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'maas'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|13\\.10|12\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "maas-region-controller", ver: "1.2+bzr1373+dfsg-0ubuntu1~12.04.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python-django-maas", ver: "1.2+bzr1373+dfsg-0ubuntu1~12.04.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "maas-region-controller", ver: "1.4+bzr1693+dfsg-0ubuntu2.3", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python-django-maas", ver: "1.4+bzr1693+dfsg-0ubuntu2.3", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "maas-region-controller", ver: "1.2+bzr1373+dfsg-0ubuntu1.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python-django-maas", ver: "1.2+bzr1373+dfsg-0ubuntu1.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

