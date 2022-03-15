if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892233" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2018-7537", "CVE-2019-19844", "CVE-2020-13254", "CVE-2020-13596" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-28 22:37:00 +0000 (Thu, 28 Feb 2019)" );
	script_tag( name: "creation_date", value: "2020-06-05 03:00:10 +0000 (Fri, 05 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for python-django (DLA-2233-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2233-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-django'
  package(s) announced via the DLA-2233-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there were two issues in Django, the Python
web development framework:

  * CVE-2020-13254: Potential a data leakage via malformed memcached
keys.

In cases where a memcached backend does not perform key validation,
passing malformed cache keys could result in a key collision, and
potential data leakage. In order to avoid this vulnerability, key
validation is added to the memcached cache backends.

  * CVE-2020-13596: Possible XSS via admin ForeignKeyRawIdWidget.

Query parameters to the admin ForeignKeyRawIdWidget were not
properly URL encoded, posing an XSS attack vector.
ForeignKeyRawIdWidget now ensures query parameters are correctly
URL encoded.

For more information, please see:

This upload also addresses test failures introduced in
1.7.11-1+deb8u3 and 1.7.11-1+deb8u8 via the fixes for CVE-2018-7537
and CVE-2019-19844 respectfully." );
	script_tag( name: "affected", value: "'python-django' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in python-django version
1.7.11-1+deb8u9.

We recommend that you upgrade your python-django packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1.7.11-1+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-common", ver: "1.7.11-1+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.7.11-1+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "1.7.11-1+deb8u9", rls: "DEB8" ) )){
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

