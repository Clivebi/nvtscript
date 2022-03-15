if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892741" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_cve_id( "CVE-2021-29425" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-14 23:15:00 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 09:50:35 +0000 (Fri, 13 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for commons-io (DLA-2741-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00016.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2741-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2741-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'commons-io'
  package(s) announced via the DLA-2741-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Lukas Euler discovered a path traversal vulnerability in commons-io, a Java
library for common useful IO related classes. When invoking the method
FileNameUtils.normalize with an improper input string, like '//../foo', or
'\\\\..\\foo', the result would be the same value, thus possibly providing access
to files in the parent directory, but not further above (thus 'limited' path
traversal), if the calling code would use the result to construct a path value." );
	script_tag( name: "affected", value: "'commons-io' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
2.5-1+deb9u1.

We recommend that you upgrade your commons-io packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libcommons-io-java", ver: "2.5-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcommons-io-java-doc", ver: "2.5-1+deb9u1", rls: "DEB9" ) )){
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

