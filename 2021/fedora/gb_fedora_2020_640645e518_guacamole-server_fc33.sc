if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878774" );
	script_version( "2021-08-23T06:00:57+0000" );
	script_cve_id( "CVE-2020-9498", "CVE-2020-9497" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-23 06:00:57 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-29 19:38:00 +0000 (Mon, 29 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 10:58:52 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Fedora: Security Advisory for guacamole-server (FEDORA-2020-640645e518)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-640645e518" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WNS7UHBOFV6JHWH5XOEZTE3BREGRSSQ3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'guacamole-server'
  package(s) announced via the FEDORA-2020-640645e518 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Guacamole is an HTML5 remote desktop gateway.

Guacamole provides access to desktop environments using remote desktop protocols
like VNC and RDP. A centralized server acts as a tunnel and proxy, allowing
access to multiple desktops through a web browser.

No browser plugins are needed, and no client software needs to be installed. The
client requires nothing more than a web browser supporting HTML5 and AJAX.

The main web application is provided by the 'guacamole-client' package." );
	script_tag( name: "affected", value: "'guacamole-server' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "guacamole-server", rpm: "guacamole-server~1.2.0~3.fc33", rls: "FC33" ) )){
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

