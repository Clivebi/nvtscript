if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875288" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2018-3282", "CVE-2016-9843", "CVE-2018-3174", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3251", "CVE-2018-3185", "CVE-2018-3277", "CVE-2018-3162", "CVE-2018-3173", "CVE-2018-3200", "CVE-2018-3284", "CVE-2018-3060", "CVE-2018-3064", "CVE-2018-3063", "CVE-2018-3058", "CVE-2018-3066", "CVE-2018-2767", "CVE-2018-3081", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819", "CVE-2018-2786", "CVE-2018-2759", "CVE-2018-2777", "CVE-2018-2810" );
	script_bugtraq_id( 106054 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-28 21:15:00 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "creation_date", value: "2018-12-04 12:40:37 +0530 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for mariadb FEDORA-2018-192148f4ff" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	script_xref( name: "FEDORA", value: "2018-192148f4ff" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VA7N3SMG43EHYFMZCVRJ6KVKUKK2VFUJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb'
  package(s) announced via the FEDORA-2018-192148f4ff advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "mariadb on Fedora 27." );
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
if(release == "FC27"){
	if(( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~10.2.19~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

