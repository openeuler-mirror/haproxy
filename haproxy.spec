%define haproxy_user      haproxy
%define haproxy_group     haproxy

%global _hardened_build   1

Name:             haproxy
Version:          2.6.6
Release:          2
Summary:          The Reliable, High Performance TCP/HTTP Load Balancer

License:          GPLv2+
URL:              https://www.haproxy.org/
Source0:          https://www.haproxy.org/download/2.6/src/%{name}-%{version}.tar.gz
Source1:          %{name}.service
Source2:          %{name}.cfg
Source3:          %{name}.logrotate
Source4:          %{name}.sysconfig

Patch0:           CVE-2023-25725.patch
Patch1:           CVE-2023-0056.patch

BuildRequires:    gcc lua-devel pcre2-devel openssl-devel systemd-devel systemd libatomic
Requires(pre):    shadow-utils
%{?systemd_requires}

%package_help
%description
HAProxy is a free, very fast and reliable solution offering high availability, load balancing,
and proxying for TCP and HTTP-based applications. It is particularly suited for very high traffic
web sites and powers quite a number of the world's most visited ones. 

%prep
%autosetup -n %{name}-%{version} -p1
%build

%make_build CPU="generic" TARGET="linux-glibc" USE_OPENSSL=1 USE_PCRE2=1 USE_SLZ=1 \
    USE_LUA=1 USE_CRYPT_H=1 USE_SYSTEMD=1 USE_LINUX_TPROXY=1 USE_GETADDRINFO=1 USE_PROMEX=1 DEFINE=-DMAX_SESS_STKCTR=12 \
    ADDINC="%{build_cflags}" ADDLIB="%{build_ldflags}"

%make_build admin/halog/halog ADDINC="%{build_cflags}" ADDLIB="%{build_ldflags}"

pushd admin/iprange
%make_build OPTIMIZE="%{build_cflags}" LDFLAGS="%{build_ldflags}"
popd

%install
install -d %{buildroot}%{_sbindir}
install haproxy  %{buildroot}%{_sbindir}
install -d %{buildroot}%{_mandir}/man1
install -m 644 doc/haproxy.1 %{buildroot}%{_mandir}/man1

pushd %{buildroot}
install -p -D -m 0644 %{SOURCE1} .%{_unitdir}/%{name}.service
install -p -D -m 0644 %{SOURCE2} .%{_sysconfdir}/haproxy/%{name}.cfg
install -p -D -m 0644 %{SOURCE3} .%{_sysconfdir}/logrotate.d/%{name}
install -p -D -m 0644 %{SOURCE4} .%{_sysconfdir}/sysconfig/%{name}
install -d -m 0755 .%{_bindir}
install -d -m 0755 .%{_localstatedir}/lib/haproxy
install -d -m 0755 .%{_sysconfdir}/haproxy/conf.d
install -d -m 0755 .%{_datadir}/haproxy
popd

install -p -m 0755 ./admin/halog/halog %{buildroot}%{_bindir}/halog
install -p -m 0755 ./admin/iprange/iprange %{buildroot}%{_bindir}/iprange
install -p -m 0755 ./admin/iprange/ip6range %{buildroot}%{_bindir}/ip6range
install -p -m 0644 ./examples/errorfiles/* %{buildroot}%{_datadir}/haproxy

for httpfile in $(find ./examples/errorfiles/ -type f) 
do
    install -p -m 0644 $httpfile %{buildroot}%{_datadir}/haproxy
done

%{__rm} -rf ./examples/errorfiles/
find ./examples/* -type f ! -name "*.cfg" -exec %{__rm} -f "{}" \;

textfiles=$(find ./ -type f -name '*.txt')
for textfile in ${textfiles}
do
    %{__mv} ${textfile} ${textfile}.old
    iconv --from-code ISO8859-1 --to-code UTF-8 --output ${textfile} ${textfile}.old
    %{__rm} -f ${textfile}.old
done

%pre
getent group %{haproxy_group} >/dev/null || groupadd -r %{haproxy_group}
getent passwd %{haproxy_user} >/dev/null || useradd -r -g %{haproxy_user} -d \
    %{_localstatedir}/lib/haproxy -s /sbin/nologin -c "haproxy" %{haproxy_user}
exit 0

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%defattr(-,root,root)
%license LICENSE
%dir %{_sysconfdir}/haproxy
%config(noreplace) %{_sysconfdir}/haproxy/%{name}.cfg
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%{_bindir}/halog
%{_bindir}/iprange
%{_bindir}/ip6range
%{_sbindir}/%{name}
%{_unitdir}/%{name}.service
%dir %{_sysconfdir}/haproxy/conf.d
%dir %{_localstatedir}/lib/haproxy
%dir %{_datadir}/haproxy
%{_datadir}/haproxy/*

%files help
%defattr(-,root,root)
%doc doc/* examples/* CHANGELOG README VERSION
%{_mandir}/man1/*

%changelog
* Sat Feb 25 2023 yaoxin <yaoxin30@h-partners.com> - 2.6.6-2
- Fix CVE-2023-25725 and CVE-2023-0056

* Sat Oct 22 2022 xinghe <xinghe2@h-partners.com> - 2.6.6-1
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:upgrade to 2.6.6

* Wed Mar 23 2022 xihaochen <xihaochen@h-partners.com> - 2.4.8-1
- update haproxy to 2.4.8

* Fri Mar 11 2022 yaoxin <yaoxin30@huawei.com> - 2.2.16-3
- Fix CVE-2022-0711

* Sat Sep 18 2021 yaoxin <yaoxin30@huawei.com> - 2.2.16-2
- Fix CVE-2021-40346

* Mon Aug 30 2021 yaoxin <yaoxin30@huawei.com> - 2.2.16-1
- Upgrade 2.2.16 to fix CVE-2021-39240

* Thu Aug 26 liwu <liwu13@huawei.com> - 2.2.1-2
- fix CVE-2021-39241,CVE-2021-39242

* Thu July 1 huanghaitao <huanghaitao8@huawei.com> - 2.2.1-1
- update to 2.2.1

* Tue Sep 15 2020 Ge Wang <wangge20@huawei.com> - 2.0.17-1
- update to 2.0.17 and modify source0 url

* Wed Aug 05 2020 lingsheng <lingsheng@huawei.com> - 2.0.14-2
- Add support for the Lua 5.4

* Wed Jul 22 2020 hanzhijun <hanzhijun1@huawei.com> - 2.0.14-1
- update to 2.0.14

* Thu May 7 2020 cuibaobao <cuibaobao1@huawei.com> - 1.8.14-5
- Type:cves
- ID: CVE-2020-11100
- SUG:restart
- DESC: fix CVE-2020-11100

* Wed Dec 4 2019 openEuler Buildteam <buildteam@openeuler.org> - 1.8.14-4
- Package init 
