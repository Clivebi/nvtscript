if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842086" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-05 06:06:18 +0100 (Thu, 05 Feb 2015)" );
	script_cve_id( "CVE-2015-0221", "CVE-2015-0219", "CVE-2015-0220", "CVE-2015-0222" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for python-django USN-2469-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-django'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2469-1 fixed vulnerabilities in Django.
The security fix for CVE-2015-0221 introduced a regression on Ubuntu 10.04 LTS and
Ubuntu 12.04 LTS when serving static content through GZipMiddleware. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

Jedediah Smith discovered that Django incorrectly handled underscores in
WSGI headers. A remote attacker could possibly use this issue to spoof
headers in certain environments. (CVE-2015-0219)
Mikko Ohtamaa discovered that Django incorrectly handled user-supplied
redirect URLs. A remote attacker could possibly use this issue to perform a
cross-site scripting attack. (CVE-2015-0220)
Alex Gaynor discovered that Django incorrectly handled reading files in
django.views.static.serve(). A remote attacker could possibly use this
issue to cause Django to consume resources, resulting in a denial of
service. (CVE-2015-0221)
Keryn Knight discovered that Django incorrectly handled forms with
ModelMultipleChoiceField. A remote attacker could possibly use this issue
to cause a large number of SQL queries, resulting in a database denial of
service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-0222)" );
	script_tag( name: "affected", value: "python-django on Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2469-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2469-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|10\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "python-django", ver: "1.3.1-4ubuntu1.15", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-django", ver: "1.1.1-2ubuntu1.16", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

