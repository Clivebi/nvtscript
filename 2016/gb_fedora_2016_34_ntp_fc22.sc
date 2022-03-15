if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807293" );
	script_version( "2020-06-23T09:25:46+0000" );
	script_tag( name: "last_modification", value: "2020-06-23 09:25:46 +0000 (Tue, 23 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-02-21 06:21:43 +0100 (Sun, 21 Feb 2016)" );
	script_cve_id( "CVE-2015-7974", "CVE-2015-8138", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8158", "CVE-2015-7704", "CVE-2015-5300", "CVE-2015-7692", "CVE-2015-7871", "CVE-2015-7702", "CVE-2015-7691", "CVE-2015-7852", "CVE-2015-7701" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for ntp FEDORA-2016-34" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ntp on Fedora 22" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-34" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177507.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC22" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC22"){
	if(( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~36.fc22", rls: "FC22" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

