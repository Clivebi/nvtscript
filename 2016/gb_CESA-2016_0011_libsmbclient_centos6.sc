if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882358" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-08 06:30:43 +0100 (Fri, 08 Jan 2016)" );
	script_cve_id( "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libsmbclient CESA-2016:0011 centos6" );
	script_tag( name: "summary", value: "Check the version of libsmbclient" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Samba is an open-source implementation
of the Server Message Block (SMB) or Common Internet File System (CIFS)
protocol, which allows PC-compatible machines to share files, printers, and
other information.

A man-in-the-middle vulnerability was found in the way 'connection signing'
was implemented by Samba. A remote attacker could use this flaw to
downgrade an existing Samba client connection and force the use of plain
text. (CVE-2015-5296)

A missing access control flaw was found in Samba. A remote, authenticated
attacker could use this flaw to view the current snapshot on a Samba share,
despite not having DIRECTORY_LIST access rights. (CVE-2015-5299)

An access flaw was found in the way Samba verified symbolic links when
creating new files on a Samba share. A remote attacker could exploit this
flaw to gain access to files outside of Samba's share path. (CVE-2015-5252)

Red Hat would like to thank the Samba project for reporting these issues.
Upstream acknowledges Stefan Metzmacher of the Samba Team and Sernet.de as
the original reporters of CVE-2015-5296, partha exablox com as the original
reporter of CVE-2015-5299, Jan 'Yenya' Kasprzak and the Computer Systems
Unit team at Faculty of Informatics, Masaryk University as the original
reporters of CVE-2015-5252.

All samba users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing this
update, the smb service will be restarted automatically." );
	script_tag( name: "affected", value: "libsmbclient on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0011" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-January/021597.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba", rpm: "samba~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-domainjoin-gui", rpm: "samba-domainjoin-gui~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-swat", rpm: "samba-swat~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-clients", rpm: "samba-winbind-clients~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-devel", rpm: "samba-winbind-devel~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-krb5-locator", rpm: "samba-winbind-krb5-locator~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-glusterfs", rpm: "samba-glusterfs~3.6.23~24.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

