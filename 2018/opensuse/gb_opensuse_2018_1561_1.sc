if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851777" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-07 05:47:55 +0200 (Thu, 07 Jun 2018)" );
	script_cve_id( "CVE-2018-9838" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for ocaml (openSUSE-SU-2018:1561-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ocaml'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ocaml fixes the following issues:

  - CVE-2018-9838: The caml_ba_deserialize function in byterun/bigarray.c in
  the standard library had an integer overflow which, in situations where
  marshalled data is accepted from an untrusted source, allows remote
  attackers to cause a denial of service (memory corruption) or possibly
  execute arbitrary code via a crafted object. [bsc#1088591]

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-559=1" );
	script_tag( name: "affected", value: "ocaml on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:1561-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00006.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "ocaml", rpm: "ocaml~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-compiler-libs", rpm: "ocaml-compiler-libs~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-compiler-libs-devel", rpm: "ocaml-compiler-libs-devel~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-debuginfo", rpm: "ocaml-debuginfo~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-debugsource", rpm: "ocaml-debugsource~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-docs", rpm: "ocaml-docs~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-emacs", rpm: "ocaml-emacs~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-ocamldoc", rpm: "ocaml-ocamldoc~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-ocamldoc-debuginfo", rpm: "ocaml-ocamldoc-debuginfo~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-rpm-macros", rpm: "ocaml-rpm-macros~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-runtime", rpm: "ocaml-runtime~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-runtime-debuginfo", rpm: "ocaml-runtime-debuginfo~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-source", rpm: "ocaml-source~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-x11", rpm: "ocaml-x11~4.03.0~4.6.1", rls: "openSUSELeap42.3" ) )){
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

