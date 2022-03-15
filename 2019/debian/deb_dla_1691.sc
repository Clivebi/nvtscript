if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891691" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2018-17581", "CVE-2018-19107", "CVE-2018-19108", "CVE-2018-19535", "CVE-2018-20097" );
	script_name( "Debian LTS: Security Advisory for exiv2 (DLA-1691-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-27 00:00:00 +0100 (Wed, 27 Feb 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00038.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "exiv2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.24-4.1+deb8u3.

We recommend that you upgrade your exiv2 packages." );
	script_tag( name: "summary", value: "Several issues have been found in exiv2, a EXIF/IPTC/XMP metadata
manipulation tool.

CVE-2018-17581
A stack overflow due to a recursive function call causing excessive
stack consumption which leads to denial of service.

CVE-2018-19107
A heap based buffer over-read caused by an integer overflow could
result in a denial of service via a crafted file.

CVE-2018-19108
There seems to be an infinite loop inside a function that can be
activated by a crafted image.

CVE-2018-19535
A heap based buffer over-read caused could result in a denial of
service via a crafted file.

CVE-2018-20097
A crafted image could result in a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "exiv2", ver: "0.24-4.1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-13", ver: "0.24-4.1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dbg", ver: "0.24-4.1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dev", ver: "0.24-4.1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-doc", ver: "0.24-4.1+deb8u3", rls: "DEB8" ) )){
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

