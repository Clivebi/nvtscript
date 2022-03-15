if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892704" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_cve_id( "CVE-2021-29505" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 05:15:00 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-06 03:00:08 +0000 (Tue, 06 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for libxstream-java (DLA-2704-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00004.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2704-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2704-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/989491" );
	script_xref( name: "URL", value: "https://x-stream.github.io/security.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxstream-java'
  package(s) announced via the DLA-2704-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in XStream, a Java library to serialize objects to and
from XML, may allow a remote attacker to execute commands of the host
only by manipulating the processed input stream.

Note: the XStream project recommends to setup its security framework
with a whitelist limited to the minimal required types, rather than
relying on the black list (which got updated to address this
vulnerability). The project is also phasing out maintenance of the
black list, see [link moved to references]." );
	script_tag( name: "affected", value: "'libxstream-java' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.4.11.1-1+deb9u3.

We recommend that you upgrade your libxstream-java packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxstream-java", ver: "1.4.11.1-1+deb9u3", rls: "DEB9" ) )){
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

