if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875818" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:22:16 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for xml-security-c FEDORA-2018-a0d02065d0" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2018-a0d02065d0" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JR5YJJECN2NEJ2UR7FL3DXONO7QBIXQP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xml-security-c'
  package(s) announced via the FEDORA-2018-a0d02065d0 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The xml-security-c library is a C++ implementation of the XML Digital
Signature specification. The library makes use of the Apache XML project&#39, s
Xerces-C XML Parser and Xalan-C XSLT processor. The latter is used for
processing XPath and XSLT transforms." );
	script_tag( name: "affected", value: "'xml-security-c' package(s) on Fedora 29." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "xml-security-c", rpm: "xml-security-c~2.0.2~1.fc29", rls: "FC29" ) )){
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
}
exit( 0 );

