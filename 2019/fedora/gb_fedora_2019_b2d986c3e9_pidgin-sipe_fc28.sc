if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875546" );
	script_version( "2021-09-01T14:01:32+0000" );
	script_cve_id( "CVE-2018-1000852", "CVE-2018-8786" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 02:09:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-04-05 02:08:13 +0000 (Fri, 05 Apr 2019)" );
	script_name( "Fedora Update for pidgin-sipe FEDORA-2019-b2d986c3e9" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-b2d986c3e9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JBY2AWULPFT5GGUWUA56Q666GLHC74YU" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'pidgin-sipe' package(s) announced via the FEDORA-2019-b2d986c3e9 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "A third-party plugin for the Pidgin multi-protocol
  instant messenger. It implements the extended version of SIP/SIMPLE used by
  various products:

  * Skype for Business

  * Microsoft Office 365

  * Microsoft Business Productivity Online Suite (BPOS)

  * Microsoft Lync Server

  * Microsoft Office Communications Server (OCS 2007/2007 R2)

  * Microsoft Live Communications Server (LCS 2003/2005)

With this plugin you should be able to replace your Microsoft Office
Communicator client with Pidgin.

This package provides the icon set for Pidgin." );
	script_tag( name: "affected", value: "'pidgin-sipe' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "pidgin-sipe", rpm: "pidgin-sipe~1.24.0~3.fc28", rls: "FC28" ) )){
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

