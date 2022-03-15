if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850644" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-03-27 06:46:14 +0100 (Fri, 27 Mar 2015)" );
	script_cve_id( "CVE-2015-0817", "CVE-2015-0818" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2015:0607-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox was updated to Firefox 36.0.4 to fix two critical security
  issues found during Pwn2Own:

  * MFSA 2015-28/CVE-2015-0818 (bmo#1144988) Privilege escalation through
  SVG navigation

  * MFSA 2015-29/CVE-2015-0817 (bmo#1145255) Code execution through
  incorrect JavaScript bounds checking elimination

  Also fixed were the following bugs:

  - Copy the icons to /usr/share/icons instead of symlinking them: in
  preparation for containerized apps (e.g. xdg-app) as well as AppStream
  metadata extraction, there are a couple locations that need to be real
  files for system integration (.desktop files, icons, mime-type info).

  - update to Firefox 36.0.1 Bugfixes:

  * Disable the usage of the ANY DNS query type (bmo#1093983)

  * Hello may become inactive until restart (bmo#1137469)

  * Print preferences may not be preserved (bmo#1136855)

  * Hello contact tabs may not be visible (bmo#1137141)

  * Accept hostnames that include an underscore character ('_')
  (bmo#1136616)

  * WebGL may use significant memory with Canvas2d (bmo#1137251)

  * Option -remote has been restored (bmo#1080319)" );
	script_tag( name: "affected", value: "MozillaFirefox on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:0607-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~36.0.4~63.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-upstream", rpm: "MozillaFirefox-branding-upstream~36.0.4~63.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-buildsymbols", rpm: "MozillaFirefox-buildsymbols~36.0.4~63.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~36.0.4~63.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~36.0.4~63.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~36.0.4~63.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~36.0.4~63.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~36.0.4~63.1", rls: "openSUSE13.1" ) )){
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

