if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892211" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2018-1285" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-02 12:59:00 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-16 03:00:05 +0000 (Sat, 16 May 2020)" );
	script_name( "Debian LTS: Security Advisory for log4net (DLA-2211-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2211-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'log4net'
  package(s) announced via the DLA-2211-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an XML external entity vulnerability
in log4net, a logging API for the ECMA Common Language Infrastructure
(CLI), sometimes referred to as 'Mono'.

This type of attack occurs when XML input containing a reference to
an internet-faced entity is processed by a weakly configured XML
parser. This attack may lead to the disclosure of confidential data,
denial of service, server side request forgery as well as other
system impacts." );
	script_tag( name: "affected", value: "'log4net' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in log4net version
1.2.10+dfsg-6+deb8u1.

We recommend that you upgrade your log4net packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblog4net-cil-dev", ver: "1.2.10+dfsg-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblog4net1.2-cil", ver: "1.2.10+dfsg-6+deb8u1", rls: "DEB8" ) )){
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

