import React from 'react';

export function SettingsPage() {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto w-full pb-12 font-sans">
      <div className="pb-4 border-b border-border">
        <h1 className="font-headline text-2xl lg:text-3xl font-bold tracking-tight text-foreground">
          Settings
        </h1>
        <p className="font-body text-xs text-muted-foreground mt-1">
          Configure application preferences and account options.
        </p>
      </div>
    </div>
  );
}
