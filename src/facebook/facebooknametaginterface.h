/*
 * Copyright (C) 2013 Jolla Ltd. <chris.adams@jollamobile.com>
 *
 * You may use this file under the terms of the BSD license as follows:
 *
 * "Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Nemo Mobile nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#ifndef FACEBOOKNAMETAGINTERFACE_H
#define FACEBOOKNAMETAGINTERFACE_H

#include "contentiteminterface.h"

#include <QtCore/QString>

/*
 * NOTE: if you construct one of these in C++ directly,
 * you MUST call classBegin() and componentCompleted()
 * directly after construction.
 */

/*
 * NOTE: this is an unidentifiable content item which
 * is read only and only creatable by the top level
 * FacebookInterface.
 */

class FacebookNameTagInterfacePrivate;
class FacebookNameTagInterface: public ContentItemInterface
{
    Q_OBJECT
    Q_PROPERTY(QString userIdentifier READ userIdentifier NOTIFY userIdentifierChanged)
    Q_PROPERTY(QString userName READ userName NOTIFY userNameChanged)
    Q_PROPERTY(QString nameTagType READ nameTagType NOTIFY nameTagTypeChanged)
    Q_PROPERTY(int offset READ offset NOTIFY offsetChanged)
    Q_PROPERTY(int length READ length NOTIFY lengthChanged)
public:
    explicit FacebookNameTagInterface(QObject *parent = 0);

    // Overrides.
    int type() const;
    // Accessors
    QString userIdentifier() const;
    QString userName() const;
    QString nameTagType() const;
    int offset() const;
    int length() const;
Q_SIGNALS:
    void userIdentifierChanged();
    void userNameChanged();
    void nameTagTypeChanged();
    void offsetChanged();
    void lengthChanged();
private:
    Q_DECLARE_PRIVATE(FacebookNameTagInterface)
};

#endif // FACEBOOKNAMETAGINTERFACE_H
