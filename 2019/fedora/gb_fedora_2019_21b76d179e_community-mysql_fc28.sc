if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875487" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2019-2420", "CVE-2019-2434", "CVE-2019-2455", "CVE-2019-2481", "CVE-2019-2482", "CVE-2019-2486", "CVE-2019-2503", "CVE-2019-2507", "CVE-2019-2510", "CVE-2019-2528", "CVE-2019-2529", "CVE-2019-2531", "CVE-2019-2532", "CVE-2019-2534", "CVE-2019-2537", "CVE-2018-3276", "CVE-2018-3200", "CVE-2018-3284", "CVE-2018-3173", "CVE-2018-3162", "CVE-2018-3247", "CVE-2018-3156", "CVE-2018-3161", "CVE-2018-3278", "CVE-2018-3282", "CVE-2018-3187", "CVE-2018-3277", "CVE-2018-3144", "CVE-2018-3133", "CVE-2018-3143", "CVE-2018-3283", "CVE-2018-3171", "CVE-2018-3251", "CVE-2018-3185", "CVE-2018-3155", "CVE-2018-2767", "CVE-2018-3056", "CVE-2018-3058", "CVE-2018-3060", "CVE-2018-3061", "CVE-2018-3062", "CVE-2018-3064", "CVE-2018-3065", "CVE-2018-3066", "CVE-2018-3070", "CVE-2018-3071", "CVE-2018-3077", "CVE-2018-3081", "CVE-2018-2755", "CVE-2018-2758", "CVE-2018-2759", "CVE-2018-2761", "CVE-2018-2762", "CVE-2018-2766", "CVE-2018-2769", "CVE-2018-2771", "CVE-2018-2773", "CVE-2018-2775", "CVE-2018-2776", "CVE-2018-2777", "CVE-2018-2778", "CVE-2018-2779", "CVE-2018-2780", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2786", "CVE-2018-2787", "CVE-2018-2810", "CVE-2018-2812", "CVE-2018-2813", "CVE-2018-2816", "CVE-2018-2817", "CVE-2018-2818", "CVE-2018-2819", "CVE-2018-2839", "CVE-2018-2846" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-21 22:29:00 +0000 (Tue, 21 May 2019)" );
	script_tag( name: "creation_date", value: "2019-03-02 04:11:37 +0100 (Sat, 02 Mar 2019)" );
	script_name( "Fedora Update for community-mysql FEDORA-2019-21b76d179e" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-21b76d179e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AFV6U7UGH37ZSMBLTCBOJYHAOWT5ZYUZ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'community-mysql'
  package(s) announced via the FEDORA-2019-21b76d179e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "community-mysql on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "community-mysql", rpm: "community-mysql~5.7.25~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

