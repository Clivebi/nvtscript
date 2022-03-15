if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874410" );
	script_version( "2021-06-14T11:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 11:00:34 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-04 05:48:47 +0200 (Fri, 04 May 2018)" );
	script_cve_id( "CVE-2018-2755", "CVE-2018-2758", "CVE-2018-2759", "CVE-2018-2761", "CVE-2018-2762", "CVE-2018-2766", "CVE-2018-2769", "CVE-2018-2771", "CVE-2018-2773", "CVE-2018-2775", "CVE-2018-2776", "CVE-2018-2777", "CVE-2018-2778", "CVE-2018-2779", "CVE-2018-2780", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2786", "CVE-2018-2787", "CVE-2018-2810", "CVE-2018-2812", "CVE-2018-2813", "CVE-2018-2816", "CVE-2018-2817", "CVE-2018-2818", "CVE-2018-2819", "CVE-2018-2839", "CVE-2018-2846", "CVE-2017-10155", "CVE-2017-10227", "CVE-2017-10268", "CVE-2017-10276", "CVE-2017-10279", "CVE-2017-10283", "CVE-2017-10286", "CVE-2017-10294", "CVE-2017-10314", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2017-3312", "CVE-2017-3633", "CVE-2017-3634", "CVE-2017-3635", "CVE-2017-3641", "CVE-2017-3647", "CVE-2017-3648", "CVE-2017-3649", "CVE-2017-3651", "CVE-2017-3652", "CVE-2017-3653" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-21 22:29:00 +0000 (Tue, 21 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for community-mysql FEDORA-2018-8b920c2b00" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'community-mysql'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "community-mysql on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-8b920c2b00" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RYCE336VZ2HRXTW67HHRQISWFGKMS4VW" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC26" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC26"){
	if(( res = isrpmvuln( pkg: "community-mysql", rpm: "community-mysql~5.7.22~1.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

