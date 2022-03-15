if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702529" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-3444", "CVE-2012-3442", "CVE-2012-3443" );
	script_name( "Debian Security Advisory DSA 2529-1 (python-django - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2529.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "python-django on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.2.3-3+squeeze3.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.1-1.

We recommend that you upgrade your python-django packages." );
	script_tag( name: "summary", value: "Jeroen Dekkers and others reported several vulnerabilities in Django,
a Python Web framework. The Common Vulnerabilities and Exposures
project defines the following issues:

CVE-2012-3442Two functions do not validate the scheme of a redirect target,
which might allow remote attackers to conduct cross-site scripting
(XSS) attacks via a data: URL.

CVE-2012-3443The ImageField class completely decompresses image data during image
validation, which allows remote attackers to cause a denial of service
(memory consumption) by uploading an image file.

CVE-2012-3444The get_image_dimensions function in the image-handling functionality
uses a constant chunk size in all attempts to determine dimensions,
which allows remote attackers to cause a denial of service (process
or thread consumption) via a large TIFF image." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-django", ver: "1.2.3-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.2.3-3+squeeze3", rls: "DEB6" ) ) != NULL){
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

